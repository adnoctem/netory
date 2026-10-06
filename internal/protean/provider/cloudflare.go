package provider

import (
	"github.com/libdns/cloudflare"
)

// KindCloudflare is the registered kind for Cloudflare.
const KindCloudflare = "cloudflare"

// Cloudflare setting keys.
const (
	// SettingAPIToken is a scoped API token with Zone.DNS:Write.
	SettingAPIToken = "api_token"

	// SettingZoneToken is an optional Zone:Read token, needed only when the
	// write token is scoped to a single zone and therefore cannot look the
	// zone up by name.
	SettingZoneToken = "zone_token"
)

func init() {
	Register(KindCloudflare, newCloudflare, SettingAPIToken, SettingZoneToken)
}

// newCloudflare builds a Cloudflare provider behind the libdns adapter.
//
// The operator supplies a scoped token. protean cannot enforce least privilege
// here - a global API key works just as well as a zone-scoped Zone.DNS:Write
// token, and the API gives no way to ask which one it was handed - so the
// documentation says to scope it and this code says why it matters rather than
// pretending to check.
func newCloudflare(cfg Config) (Provider, error) {
	token, err := cfg.Require(SettingAPIToken)
	if err != nil {
		return nil, err
	}

	client := &cloudflare.Provider{
		APIToken:  token,
		ZoneToken: cfg.Setting(SettingZoneToken),
	}

	return &libdnsAdapter{
		name:   cfg.Name,
		kind:   KindCloudflare,
		zone:   cfg.Zone,
		client: client,
		redacted: map[string]string{
			SettingAPIToken:  setOrAbsent(token),
			SettingZoneToken: setOrAbsent(cfg.Setting(SettingZoneToken)),
		},
	}, nil
}

// setOrAbsent renders a credential's presence without its value.
func setOrAbsent(value string) string {
	if value == "" {
		return "(not set)"
	}

	return "(set)"
}
