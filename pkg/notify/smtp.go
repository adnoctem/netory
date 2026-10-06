package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/secret"
)

// KindSMTP is the registered kind for the SMTP transport.
const KindSMTP = "smtp"

// SMTP setting keys.
const (
	SettingHost     = "host"
	SettingPort     = "port"
	SettingUsername = "username"
	SettingPassword = "password"
	SettingFrom     = "from"
	SettingTo       = "to"
)

// implicitTLSPort is the submission port that expects TLS from the first byte
// rather than an upgrade.
const implicitTLSPort = 465

// smtpDialTimeout bounds a connection attempt. Without it, a relay that
// accepts the TCP connection and then goes silent would hold a delivery slot
// until the bus's context expires.
const smtpDialTimeout = 30 * time.Second

func init() {
	// The password is declared secret, so `notifier list` shows "(set)" rather
	// than the value. The username is not: knowing which account is used is
	// operationally useful and is not a credential on its own.
	Register(KindSMTP, newSMTP, SettingPassword)
}

// smtpNotifier delivers events as mail through the operator's relay.
type smtpNotifier struct {
	name     string
	host     string
	port     int
	username string
	password string
	from     string
	to       []string
}

// newSMTP builds an SMTP notifier. The service secret is unused: SMTP
// credentials are supplied by the operator, not derived.
func newSMTP(cfg Config, _ *secret.Secret) (Notifier, error) {
	host, err := cfg.require(SettingHost)
	if err != nil {
		return nil, err
	}

	from, err := cfg.require(SettingFrom)
	if err != nil {
		return nil, err
	}

	rawTo, err := cfg.require(SettingTo)
	if err != nil {
		return nil, err
	}

	// A comma-separated list, since settings are a flat string map.
	var to []string
	for _, addr := range strings.Split(rawTo, ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			to = append(to, addr)
		}
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("setting %q contains no addresses", SettingTo)
	}

	// Addresses end up in headers and in the SMTP envelope, so they are
	// validated here rather than at send time: a malformed address configured
	// once would otherwise fail every delivery forever, and the operator would
	// see it as a notification outage rather than a configuration error.
	for _, addr := range append([]string{from}, to...) {
		if err := validateAddress(addr); err != nil {
			return nil, err
		}
	}

	port := 587
	if raw := cfg.Setting(SettingPort); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			return nil, fmt.Errorf("setting %q must be a port number, got %q", SettingPort, raw)
		}

		port = parsed
	}

	return &smtpNotifier{
		name:     cfg.Name,
		host:     host,
		port:     port,
		username: cfg.Setting(SettingUsername),
		password: cfg.Setting(SettingPassword),
		from:     from,
		to:       to,
	}, nil
}

func (s *smtpNotifier) Name() string { return s.name }
func (s *smtpNotifier) Kind() string { return KindSMTP }

// Redacted implements Notifier.
func (s *smtpNotifier) Redacted() map[string]string {
	out := map[string]string{
		SettingHost: s.host,
		SettingPort: strconv.Itoa(s.port),
		SettingFrom: s.from,
		SettingTo:   strings.Join(s.to, ", "),
	}

	if s.username != "" {
		out[SettingUsername] = s.username
	}

	if s.password != "" {
		out[SettingPassword] = "(set)"
	}

	return out
}

// Deliver sends one message. It makes a single attempt; retries belong to the
// outbox.
func (s *smtpNotifier) Deliver(ctx context.Context, e event.Event) error {
	message, err := s.compose(e)
	if err != nil {
		return err
	}

	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// Quit sends QUIT and closes; if it fails the connection is closed
		// anyway, and the delivery has already been reported either way.
		_ = client.Quit()
	}()

	if s.username != "" || s.password != "" {
		auth := smtp.PlainAuth("", s.username, s.password, s.host)

		// net/smtp refuses PLAIN over an unencrypted connection unless the
		// host is localhost, so a misconfiguration that would put the relay
		// password on the wire in cleartext fails here rather than succeeding
		// quietly.
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("notify: smtp %q: authenticate to %s: %w", s.name, s.address(), err)
		}
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("notify: smtp %q: MAIL FROM %s: %w", s.name, s.from, err)
	}

	for _, addr := range s.to {
		if err := client.Rcpt(addr); err != nil {
			return fmt.Errorf("notify: smtp %q: RCPT TO %s: %w", s.name, addr, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp %q: DATA: %w", s.name, err)
	}

	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()

		return fmt.Errorf("notify: smtp %q: write message: %w", s.name, err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("notify: smtp %q: complete message: %w", s.name, err)
	}

	return nil
}

// address is the relay's host:port.
func (s *smtpNotifier) address() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.port))
}

// connect dials the relay and brings the connection up to TLS.
//
// The two submission ports differ in *when* TLS starts, not whether: 465
// expects TLS from the first byte, 587 and 25 negotiate it with STARTTLS. Both
// end encrypted - there is no plaintext path, because the relay password and
// the event contents both travel this connection.
func (s *smtpNotifier) connect(ctx context.Context) (*smtp.Client, error) {
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	tlsConfig := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}

	if s.port == implicitTLSPort {
		conn, err := tls.DialWithDialer(dialer, "tcp", s.address(), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("notify: smtp %q: connect to %s over TLS: %w", s.name, s.address(), err)
		}

		client, err := smtp.NewClient(conn, s.host)
		if err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("notify: smtp %q: SMTP handshake with %s: %w", s.name, s.address(), err)
		}

		return client, nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", s.address())
	if err != nil {
		return nil, fmt.Errorf("notify: smtp %q: connect to %s: %w", s.name, s.address(), err)
	}

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("notify: smtp %q: SMTP handshake with %s: %w", s.name, s.address(), err)
	}

	// A relay that cannot upgrade is a failure, not a reason to continue in
	// cleartext. Silently downgrading is how a credential ends up on the wire.
	if ok, _ := client.Extension("STARTTLS"); !ok {
		_ = client.Close()

		return nil, fmt.Errorf(
			"notify: smtp %q: %s does not offer STARTTLS, refusing to send in cleartext",
			s.name, s.address(),
		)
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		_ = client.Close()

		return nil, fmt.Errorf("notify: smtp %q: STARTTLS with %s: %w", s.name, s.address(), err)
	}

	return client, nil
}
