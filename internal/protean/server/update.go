package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/provider"
)

// UpdatePath is the DynDNS2 endpoint. The path is fixed by the protocol:
// clients have it compiled in or offer it as a preset.
const UpdatePath = "/nic/update"

// providerTimeout bounds one provider API call, so a slow provider cannot hold
// an update request open indefinitely.
const providerTimeout = 30 * time.Second

// handleUpdate serves the DynDNS2 update endpoint.
//
// The order of the checks is deliberate: the cheap rejections come first, so an
// unauthenticated or rate-limited request never costs a provider call or a
// store write beyond its own counter.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	source, err := s.source.Source(r)
	if err != nil {
		// Without a source address there is no rate limiting and no sensible
		// audit record, so the request is refused rather than served blind.
		s.log.Error("refusing an update with no determinable source address", "error", err)
		RespServerError.write(w)

		return
	}

	// A token travelling in the clear is a disclosed token, and the client
	// will keep sending it every few minutes. Refusing is the only useful
	// response.
	if s.source.Encryption(r) == Plaintext {
		s.log.Warn("refusing a plaintext update request: HTTP Basic sends the token on every request",
			"source", source.String())
		RespBadAuth.write(w)

		return
	}

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		s.log.Error("could not read settings", "error", err)
		RespServerError.write(w)

		return
	}

	// Per-source limiting comes before authentication, because its job is to
	// slow down an attacker guessing tokens - a limit applied only after a
	// successful authentication would never see them.
	decision, err := s.limiter.Allow(ctx, SourceKey(source.String()),
		settings.RateLimitPerSource, settings.RateLimitWindow)
	if err != nil {
		s.log.Error("could not apply the per-source rate limit", "source", source.String(), "error", err)
		RespServerError.write(w)

		return
	}

	if !decision.Allowed {
		s.writeAbuse(w, decision)
		s.log.Warn("source rate limited", "source", source.String(), "count", decision.Count)

		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		// Credentials in the query string are refused rather than accepted,
		// and the log says why. Several dynDNS provider guides use that form,
		// and a FRITZ!Box will happily substitute <username> and <pass> into a
		// URL - so an operator who followed a generic guide gets a diagnosis
		// here instead of an unexplained badauth.
		if queryCarriesCredentials(r) {
			s.log.Warn("refusing an update whose credentials were sent in the query string: "+
				"a token in a URL appears in every access log and proxy log it passes through. "+
				"Configure the credentials in the client's username and password fields instead, "+
				"which sends them as HTTP Basic authentication",
				"source", source.String())
		}

		// The realm invites a client to retry with credentials, which is what
		// a browser or a curl-based check will do.
		w.Header().Set("WWW-Authenticate", `Basic realm="protean", charset="UTF-8"`)
		RespBadAuth.write(w)

		return
	}

	// The hostname may be claimed explicitly, through the `hostname` parameter
	// or through the Basic auth username. Neither is required: the token
	// belongs to exactly one host, so it already says which host is being
	// updated. See claimedHostname for why both are optional.
	claimed, response := claimedHostname(r, username)
	if response != "" {
		s.log.Warn("update rejected: the hostname given is not a fully-qualified name",
			"hostname", r.URL.Query().Get("hostname"), "source", source.String())
		response.write(w)

		return
	}

	token, err := s.authenticate(ctx, claimed, password)
	if err != nil {
		s.recordAuthFailure(ctx, claimed, source, settings)

		switch {
		case errors.Is(err, app.ErrTokenNotFound):
			RespBadAuth.write(w)
		case errors.Is(err, app.ErrTokenMismatch):
			// The token is valid but belongs to a different host than the one
			// claimed. That is a scoping failure rather than a credential
			// failure, so it is reported as such.
			s.log.Warn("update rejected: the token does not belong to the hostname given",
				"claimed", claimed, "source", source.String())
			RespNoHost.write(w)
		default:
			s.log.Error("could not authenticate an update", "claimed", claimed, "error", err)
			RespServerError.write(w)
		}

		return
	}

	// The token's own host is authoritative from here on, whether or not one
	// was claimed.
	host, err := s.state.Hosts.Get(ctx, token.Host)
	if err != nil {
		if errors.Is(err, app.ErrHostNotFound) {
			// A valid token for a host that no longer exists. Unusual - host
			// removal revokes its tokens - but a token outliving its host must
			// not be treated as authorised.
			s.log.Warn("valid token for a host that is not configured",
				"host", token.Host, "token", token.ID)
			RespNoHost.write(w)

			return
		}

		s.log.Error("could not read the host", "host", token.Host, "error", err)
		RespServerError.write(w)

		return
	}

	// Per-host limiting, after authentication: this one catches a
	// misconfigured client of a legitimate host, and each update it allows is
	// a provider API call.
	decision, err = s.limiter.Allow(ctx, HostKey(host.Name),
		settings.RateLimitPerHost, settings.RateLimitWindow)
	if err != nil {
		s.log.Error("could not apply the per-host rate limit", "host", host.Name, "error", err)
		RespServerError.write(w)

		return
	}

	if !decision.Allowed {
		s.writeAbuse(w, decision)
		s.log.Warn("host rate limited", "host", host.Name, "count", decision.Count)

		return
	}

	s.applyUpdate(w, r, host, source)
}

// credentialParams are the query parameters that dynDNS provider guides use to
// carry credentials in a URL. protean does not accept any of them; they are
// recognised only so the refusal can explain itself.
var credentialParams = []string{"password", "pass", "passwd", "pw", "token", "apikey", "api_key"}

// queryCarriesCredentials reports whether the request looks like it was trying
// to authenticate through the URL.
func queryCarriesCredentials(r *http.Request) bool {
	query := r.URL.Query()
	for _, param := range credentialParams {
		if query.Get(param) != "" {
			return true
		}
	}

	return false
}

// claimedHostname works out which hostname, if any, the request asserts.
//
// Three shapes have to work, because all three exist in the wild:
//
//   - ddclient and inadyn send the hostname as the Basic auth username, which
//     is what DynDNS2 conventionally implies.
//   - A FRITZ!Box has separate Username, Password and "Domain name" fields and
//     authenticates with HTTP Basic from the first two, so the username it
//     sends is whatever the operator typed. The hostname arrives through the
//     `hostname` parameter, if the update URL references <domain> at all.
//   - Some clients send neither, because the credential identifies the host at
//     the provider's end. protean's tokens work exactly that way.
//
// So an empty result is not an error: the token identifies the host. A
// `hostname` parameter that is present but not a fully-qualified name is an
// error, because the client meant to assert something and got it wrong.
func claimedHostname(r *http.Request, username string) (string, Response) {
	if requested := strings.TrimSpace(r.URL.Query().Get("hostname")); requested != "" {
		normalised := app.NormaliseHostname(requested)
		if err := app.ValidateHostname(normalised); err != nil {
			return "", RespNotFQDN
		}

		return normalised, ""
	}

	// The username is only treated as a hostname when it actually looks like
	// one. A FRITZ!Box username such as "fritzbox" or an account name is not a
	// claim about which host to update, and must not be read as one.
	normalised := app.NormaliseHostname(username)
	if app.ValidateHostname(normalised) == nil {
		return normalised, ""
	}

	return "", ""
}

// authenticate resolves the token, checking the claimed host when one was
// given.
func (s *Server) authenticate(ctx context.Context, claimed, password string) (app.Token, error) {
	if claimed == "" {
		return s.state.Tokens.Authenticate(ctx, password)
	}

	return s.state.Tokens.AuthenticateFor(ctx, claimed, password)
}

// addressUpdate is one family's requested change.
type addressUpdate struct {
	ipv6    bool
	address string
}

// applyUpdate resolves the requested addresses and writes the changed ones.
func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request, host app.Host, source netip.Addr) {
	ctx := r.Context()

	requested, response := s.resolveAddresses(r, host, source)
	if response != "" {
		response.write(w)

		return
	}

	// Nothing the host manages was supplied.
	if len(requested) == 0 {
		RespNoHost.write(w)

		return
	}

	// Split into what actually changed and what did not. An unchanged address
	// costs nothing downstream (section 6.4), which is the single most
	// important performance property of this endpoint: a router re-sending the
	// same address every five minutes is the normal case.
	var (
		changed  []addressUpdate
		answered []string
	)
	for _, update := range requested {
		// Every requested address is echoed back, changed or not: DynDNS2
		// clients read the address out of the response to confirm what the
		// server believes, and a `nochg` with no address reads as a failure to
		// some of them.
		answered = append(answered, update.address)

		if host.LastAddress(update.ipv6) == update.address {
			continue
		}

		changed = append(changed, update)
	}

	if len(changed) == 0 {
		RespNoChange.write(w, answered...)
		s.log.Debug("update unchanged", "host", host.Name, "addresses", strings.Join(answered, ","))

		return
	}

	if err := s.writeToProvider(ctx, host, changed); err != nil {
		var apiErr *provider.APIError
		if errors.As(err, &apiErr) && apiErr.Permanent() {
			// A rejected credential or a malformed record fails identically
			// every time, so it is reported as a provider problem rather than
			// a transient one.
			s.state.Publish(ctx, app.ProviderFailed(host.Provider, err))
		}

		s.log.Error("provider update failed", "host", host.Name, "provider", host.Provider, "error", err)
		s.state.Publish(ctx, app.HostUpdateFailed(host.Name, host.Provider, err))
		RespDNSErr.write(w)

		return
	}

	var ipv4, ipv6 string
	for _, update := range changed {
		if update.ipv6 {
			ipv6 = update.address
		} else {
			ipv4 = update.address
		}
	}

	// Recorded after the provider call succeeds, never before. The stored
	// address is what answers `nochg`, so recording it first would make a
	// failed update look applied and the client would stop retrying.
	if err := s.state.Hosts.RecordUpdate(ctx, host.Name, ipv4, ipv6); err != nil {
		// The provider has the new address, so the update did happen; only
		// protean's record of it is stale, which costs one redundant provider
		// call next time. Reporting failure here would make the client retry
		// an update that already succeeded.
		s.log.Error("provider updated but the host record could not be saved",
			"host", host.Name, "error", err)
	}

	s.log.Info("host updated", "host", host.Name, "provider", host.Provider,
		slog.String("ipv4", ipv4), slog.String("ipv6", ipv6), "source", source.String())

	s.state.Publish(ctx, app.HostUpdated(host.Name, ipv4, ipv6))
	RespGood.write(w, answered...)
}

// resolveAddresses works out which addresses to write.
//
// myip and myipv6 take precedence over the request's source address, which
// matters on a DS-Lite connection: there the IPv4 address protean observes
// belongs to the ISP's carrier-grade NAT, not the subscriber, so the client's
// own idea of its address is the only correct one (section 6.3).
//
// That precedence is why an explicit address is never silently replaced by the
// source address. A client that states an address protean cannot publish is
// refused, not quietly corrected: substituting the source address there would
// publish the carrier-grade NAT address on exactly the connections section 6.3
// is about, and the client would have no way to tell.
func (s *Server) resolveAddresses(
	r *http.Request, host app.Host, source netip.Addr,
) ([]addressUpdate, Response) {
	query := r.URL.Query()

	var (
		updates  []addressUpdate
		explicit bool
	)

	// myip may carry either family - some clients send an IPv6 address in it -
	// so it is dispatched by what it parses as rather than by its name.
	for _, param := range []string{"myip", "myipv6"} {
		raw := strings.TrimSpace(query.Get(param))
		if raw == "" {
			continue
		}

		explicit = true

		// A comma-separated pair is accepted: ddclient sends "v4,v6" in myip
		// when configured for both families.
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}

			addr, err := netip.ParseAddr(entry)
			if err != nil {
				s.log.Warn("update rejected: unparsable address",
					"host", host.Name, "parameter", param, "value", entry)

				return nil, RespDNSErr
			}

			addr = addr.Unmap()

			update, ok := updateFor(host, addr)
			if !ok {
				// Either unpublishable, or a family this host does not manage.
				// The first is a client error worth reporting; the second is
				// legitimate - a host managing only A, sent both families,
				// should write the A record and ignore the rest.
				if !publishable(addr) {
					s.log.Warn("update rejected: address is not publishable in a public zone",
						"host", host.Name, "parameter", param, "address", addr.String())

					return nil, RespDNSErr
				}

				continue
			}

			updates = appendUnique(updates, update)
		}
	}

	// An explicit address was given but nothing came of it, which means every
	// family the client sent is one this host does not manage.
	if explicit && len(updates) == 0 {
		s.log.Warn("update rejected: none of the supplied families are managed for this host",
			"host", host.Name, "manages_a", host.ManageA, "manages_aaaa", host.ManageAAAA)

		return nil, RespNoHost
	}

	if explicit {
		return updates, ""
	}

	// No explicit address: fall back to where the request came from, which is
	// what a client that sends no parameters expects.
	if update, ok := updateFor(host, source); ok {
		updates = appendUnique(updates, update)
	}

	return updates, ""
}

// publishable reports whether an address belongs in a public DNS record.
//
// A private, loopback or link-local address is almost always a misconfigured
// client reporting its LAN address. Publishing one points the name at
// somewhere unreachable from the internet, which looks like a working update
// and is not.
func publishable(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}

	// IsGlobalUnicast is true for private ranges and for IPv6 unique-local
	// addresses, so both are excluded explicitly.
	return !addr.IsPrivate()
}

// updateFor builds an update for an address, if it is publishable and the host
// manages that family.
func updateFor(host app.Host, addr netip.Addr) (addressUpdate, bool) {
	if !publishable(addr) {
		return addressUpdate{}, false
	}

	ipv6 := !addr.Is4()
	if !host.Manages(ipv6) {
		return addressUpdate{}, false
	}

	return addressUpdate{ipv6: ipv6, address: addr.String()}, true
}

// appendUnique adds an update unless that family is already present, so the
// first value given for a family wins.
func appendUnique(updates []addressUpdate, update addressUpdate) []addressUpdate {
	for _, existing := range updates {
		if existing.ipv6 == update.ipv6 {
			return updates
		}
	}

	return append(updates, update)
}

// writeToProvider sends the changed records to the host's provider.
func (s *Server) writeToProvider(ctx context.Context, host app.Host, changed []addressUpdate) error {
	cfg, err := s.state.Providers.Get(ctx, host.Provider)
	if err != nil {
		return err
	}

	instance, err := provider.New(cfg)
	if err != nil {
		return err
	}

	name, err := host.RelativeName(cfg.Zone)
	if err != nil {
		return err
	}

	records := make([]provider.Record, 0, len(changed))
	for _, update := range changed {
		recordType := provider.TypeA
		if update.ipv6 {
			recordType = provider.TypeAAAA
		}

		records = append(records, provider.Record{
			Name:  name,
			Type:  recordType,
			Value: update.address,
			TTL:   host.TTL,
		})
	}

	// A timeout of protean's own, not the request's: a client that gives up
	// mid-update should not leave the provider call half-made, and a provider
	// that never answers must not hold the handler forever.
	callCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	if err := instance.Upsert(callCtx, cfg.Zone, records); err != nil {
		return fmt.Errorf("provider %q: %w", host.Provider, err)
	}

	return nil
}

// recordAuthFailure counts a failed authentication and emits auth.failed once
// the threshold is crossed.
//
// Counting per host and per source separately answers two different questions:
// one host failing repeatedly is a client with a stale token, while one source
// failing against many hosts is someone guessing. A single counter would
// conflate them.
//
// The host is empty when the request claimed no hostname, which is legitimate -
// the token identifies the host, so a client need not assert one. Only the
// source is counted in that case; attributing the failure to a host protean had
// to guess would put the wrong name in an alert.
func (s *Server) recordAuthFailure(
	ctx context.Context, host string, source netip.Addr, settings app.Settings,
) {
	threshold := settings.AuthFailureThreshold
	if threshold <= 0 {
		return
	}

	subjects := map[string]string{source.String(): "source"}
	if host != "" {
		subjects[host] = "host"
	}

	for subject, label := range subjects {
		if subject == "" {
			continue
		}

		decision, err := s.limiter.Allow(ctx, FailureKey(subject), threshold, settings.RateLimitWindow)
		if err != nil {
			s.log.Error("could not count an authentication failure", "subject", subject, "error", err)

			continue
		}

		// Exactly at the threshold, so one event fires rather than one per
		// subsequent failure. The bus deduplicates by type and subject as
		// well, which covers the window after the counter rolls over.
		if decision.Count == int64(threshold) {
			s.log.Warn("repeated authentication failures",
				label, subject, "failures", decision.Count, "source", source.String())

			sourceField := source.String()
			if label == "source" {
				sourceField = ""
			}

			s.state.Publish(ctx, app.AuthFailed(subject, sourceField, int(decision.Count)))
		}
	}
}

// writeAbuse answers a rate-limited request.
func (s *Server) writeAbuse(w http.ResponseWriter, decision Decision) {
	// Retry-After is what turns a limit into back-pressure rather than a wall:
	// a client that respects it stops hammering, which is the actual goal.
	w.Header().Set("Retry-After", retryAfterSeconds(decision.RetryAfter))
	RespAbuse.write(w)
}

// retryAfterSeconds renders a duration as whole seconds for Retry-After.
func retryAfterSeconds(d time.Duration) string {
	seconds := int(d.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}

	return strconv.Itoa(seconds)
}
