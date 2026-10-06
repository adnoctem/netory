package provider

import (
	"fmt"
	"strconv"
	"time"

	"github.com/libdns/route53"
)

// KindRoute53 is the registered kind for Amazon Route 53.
const KindRoute53 = "route53"

// Route53 setting keys.
const (
	SettingRegion          = "region"
	SettingAccessKeyID     = "access_key_id"
	SettingSecretAccessKey = "secret_access_key"
	SettingSessionToken    = "session_token"
	SettingHostedZoneID    = "hosted_zone_id"
	SettingWaitForSync     = "wait_for_sync"
	SettingMaxWait         = "max_wait"
)

func init() {
	Register(
		KindRoute53, newRoute53,
		SettingAccessKeyID, SettingSecretAccessKey, SettingSessionToken,
	)
}

// newRoute53 builds a Route 53 provider behind the libdns adapter.
//
// Credentials are optional: left unset, the AWS SDK falls back to its own
// chain - instance metadata, the task role, the shared credentials file. That
// is usually what an operator on EC2 or EKS wants, and it is better than
// copying a long-lived access key into protean's database. Explicit keys are
// supported for everyone else.
//
// Note that the access key id is treated as a credential and redacted. It is
// not secret in the cryptographic sense, but it identifies an AWS account and
// there is no operational reason to print it in `provider list`.
func newRoute53(cfg Config) (Provider, error) {
	client := &route53.Provider{
		Region:          cfg.Setting(SettingRegion),
		AccessKeyId:     cfg.Setting(SettingAccessKeyID),
		SecretAccessKey: cfg.Setting(SettingSecretAccessKey),
		SessionToken:    cfg.Setting(SettingSessionToken),
		HostedZoneID:    cfg.Setting(SettingHostedZoneID),
	}

	// An access key without its secret, or the reverse, is a configuration
	// that silently falls back to the SDK's credential chain and then fails
	// somewhere far from the mistake.
	hasID := cfg.Setting(SettingAccessKeyID) != ""
	hasSecret := cfg.Setting(SettingSecretAccessKey) != ""
	if hasID != hasSecret {
		return nil, fmt.Errorf(
			"settings %q and %q must be set together, or both left unset to use the AWS credential chain",
			SettingAccessKeyID, SettingSecretAccessKey,
		)
	}

	if raw := cfg.Setting(SettingWaitForSync); raw != "" {
		wait, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("setting %q must be a boolean, got %q", SettingWaitForSync, raw)
		}

		client.WaitForRoute53Sync = wait
	}

	if raw := cfg.Setting(SettingMaxWait); raw != "" {
		maxWait, err := time.ParseDuration(raw)
		if err != nil || maxWait <= 0 {
			return nil, fmt.Errorf("setting %q must be a positive duration, got %q", SettingMaxWait, raw)
		}

		client.Route53MaxWait = maxWait
	}

	redacted := map[string]string{
		SettingAccessKeyID:     setOrAbsent(cfg.Setting(SettingAccessKeyID)),
		SettingSecretAccessKey: setOrAbsent(cfg.Setting(SettingSecretAccessKey)),
	}

	if region := cfg.Setting(SettingRegion); region != "" {
		redacted[SettingRegion] = region
	}

	if zoneID := cfg.Setting(SettingHostedZoneID); zoneID != "" {
		redacted[SettingHostedZoneID] = zoneID
	}

	if !hasID {
		redacted["credentials"] = "AWS credential chain (instance or task role, shared config)"
	}

	return &libdnsAdapter{
		name:     cfg.Name,
		kind:     KindRoute53,
		zone:     cfg.Zone,
		client:   client,
		redacted: redacted,
	}, nil
}
