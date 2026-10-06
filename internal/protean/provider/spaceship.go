package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KindSpaceship is the registered kind for Spaceship.
const KindSpaceship = "spaceship"

// Spaceship setting keys.
const (
	SettingAPIKey    = "api_key"
	SettingAPISecret = "api_secret"
	SettingEndpoint  = "endpoint"
)

// spaceshipBaseURL is Spaceship's API root.
const spaceshipBaseURL = "https://spaceship.dev/api/v1"

// spaceshipPageSize is the page size for listing records. 500 is the
// documented maximum, so a zone of any realistic size is read in one or two
// calls.
const spaceshipPageSize = 500

// spaceshipTimeout bounds one API call.
const spaceshipTimeout = 30 * time.Second

// maxSpaceshipErrorBytes bounds how much of an error response is quoted.
const maxSpaceshipErrorBytes = 4 << 10

// spaceshipMaxPages caps pagination, so a provider reporting a nonsensical
// total cannot loop forever on the update path.
const spaceshipMaxPages = 64

func init() {
	Register(KindSpaceship, newSpaceship, SettingAPIKey, SettingAPISecret)
}

// spaceshipProvider is a native Spaceship implementation.
//
// Written against the API directly rather than through libdns, because the
// available libdns implementations for Spaceship are several competing
// third-party packages of varying maturity - protean's design document
// (section 7.2) calls for evaluating them or writing one, and the surface
// needed here is three endpoints.
//
// Spaceship's API is separate from Namecheap's. A domain hosted at Namecheap
// itself needs a different provider.
type spaceshipProvider struct {
	name     string
	zone     string
	key      string
	secret   string
	endpoint string
	client   *http.Client
}

// enforce implementation of the interfaces
var (
	_ Provider = (*spaceshipProvider)(nil)
	_ Verifier = (*spaceshipProvider)(nil)
)

func newSpaceship(cfg Config) (Provider, error) {
	key, err := cfg.Require(SettingAPIKey)
	if err != nil {
		return nil, err
	}

	secret, err := cfg.Require(SettingAPISecret)
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimSuffix(cfg.Setting(SettingEndpoint), "/")
	if endpoint == "" {
		endpoint = spaceshipBaseURL
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("setting %q must be an https URL, got %q", SettingEndpoint, endpoint)
	}

	return &spaceshipProvider{
		name:     cfg.Name,
		zone:     cfg.Zone,
		key:      key,
		secret:   secret,
		endpoint: endpoint,
		client:   &http.Client{Timeout: spaceshipTimeout},
	}, nil
}

func (s *spaceshipProvider) Name() string { return s.name }
func (s *spaceshipProvider) Kind() string { return KindSpaceship }

// Redacted implements Provider.
func (s *spaceshipProvider) Redacted() map[string]string {
	return map[string]string{
		"zone":           s.zone,
		SettingAPIKey:    setOrAbsent(s.key),
		SettingAPISecret: setOrAbsent(s.secret),
		SettingEndpoint:  s.endpoint,
	}
}

// spaceshipRecord is one record in Spaceship's API.
//
// A and AAAA carry their address in "address"; TXT carries its text in
// "value". One struct with both fields and omitempty covers all three, and
// which one is populated is decided by type.
type spaceshipRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	TTL     int    `json:"ttl,omitempty"`
	Address string `json:"address,omitempty"`
	Value   string `json:"value,omitempty"`
}

// recordValue returns whichever value field applies to the record's type.
func (r spaceshipRecord) recordValue() string {
	if strings.EqualFold(r.Type, TypeTXT) {
		return r.Value
	}

	return r.Address
}

// toSpaceship converts a protean record.
func toSpaceship(record Record) spaceshipRecord {
	out := spaceshipRecord{
		Type: record.Type,
		Name: spaceshipName(record.Name),
		TTL:  int(record.ValidTTL().Seconds()),
	}

	if record.Type == TypeTXT {
		out.Value = record.Value
	} else {
		out.Address = record.Value
	}

	return out
}

// spaceshipName maps protean's empty apex name to Spaceship's "@".
func spaceshipName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "@"
	}

	return name
}

// proteanSpaceshipName maps Spaceship's "@" back to protean's empty name.
func proteanSpaceshipName(name string) string {
	if name == "@" {
		return ""
	}

	return name
}

// Get implements Provider.
func (s *spaceshipProvider) Get(ctx context.Context, zone, name string) ([]Record, error) {
	zone = s.resolveZone(zone)

	all, err := s.list(ctx, zone)
	if err != nil {
		return nil, err
	}

	want := spaceshipName(name)

	var records []Record
	for _, record := range all {
		// Spaceship matches names case-insensitively for every type, so the
		// comparison here does too. The record *value* is a different matter:
		// TXT values are case-sensitive, which matters in matchesValue below.
		if !strings.EqualFold(record.Name, want) {
			continue
		}

		switch strings.ToUpper(record.Type) {
		case TypeA, TypeAAAA, TypeTXT:
		default:
			continue
		}

		records = append(records, Record{
			Name:  proteanSpaceshipName(record.Name),
			Type:  strings.ToUpper(record.Type),
			Value: record.recordValue(),
			TTL:   time.Duration(record.TTL) * time.Second,
		})
	}

	return records, nil
}

// Upsert implements Provider.
//
// Spaceship's save endpoint is documented as creating records, with a
// conflict-resolution checker that `force` disables; it is not documented to
// replace an existing RRset the way libdns's SetRecords does. So the stale
// records for each (name, type) being written are deleted first, and only then
// is the new one saved.
//
// Deleting first leaves a brief window in which the name does not resolve. That
// is the better of the two failures available here: the alternative risks
// ending up with two A records for one name, which sends half the traffic to an
// address that is no longer the client's and persists until someone notices. A
// sub-second gap during a change that was about to invalidate every cached
// answer anyway is cheap by comparison.
//
// See protean section 10.2 - the exact replace semantics of the save endpoint
// want confirming against a live account.
func (s *spaceshipProvider) Upsert(ctx context.Context, zone string, records []Record) error {
	if err := ValidateAll(records); err != nil {
		return fmt.Errorf("provider %q: %w", s.name, err)
	}

	zone = s.resolveZone(zone)

	existing, err := s.list(ctx, zone)
	if err != nil {
		return err
	}

	// Collect the stale records: same name and type as something being
	// written, different value.
	var stale []spaceshipRecord
	for _, current := range existing {
		for _, wanted := range records {
			if !strings.EqualFold(current.Name, spaceshipName(wanted.Name)) {
				continue
			}

			if !strings.EqualFold(current.Type, wanted.Type) {
				continue
			}

			if matchesValue(current, wanted) {
				continue
			}

			stale = append(stale, current)

			break
		}
	}

	if len(stale) > 0 {
		if err := s.deleteRecords(ctx, zone, stale); err != nil {
			return err
		}
	}

	items := make([]spaceshipRecord, 0, len(records))
	for _, record := range records {
		items = append(items, toSpaceship(record))
	}

	// force stays false. It disables Spaceship's conflict-resolution checker
	// for the whole zone update, which could let through a combination DNS
	// does not permit - a CNAME alongside an A record at the same name, say.
	// The stale records are already gone, so there should be nothing to
	// conflict with.
	body := struct {
		Force bool              `json:"force"`
		Items []spaceshipRecord `json:"items"`
	}{Items: items}

	if err := s.do(ctx, http.MethodPut, "/dns/records/"+url.PathEscape(zone), body, nil); err != nil {
		return fmt.Errorf("provider %q: write %d record(s) to zone %q: %w", s.name, len(records), zone, err)
	}

	return nil
}

// matchesValue reports whether an existing record already holds the wanted
// value.
//
// TXT comparison is case-sensitive and the others are not, matching
// Spaceship's own matching rules: an A record's value is an IP address where
// case is meaningless, while a TXT record's text is data and "ABC" is not
// "abc".
func matchesValue(current spaceshipRecord, wanted Record) bool {
	if strings.EqualFold(current.Type, TypeTXT) {
		return current.recordValue() == wanted.Value
	}

	return strings.EqualFold(current.recordValue(), wanted.Value)
}

// Delete implements Provider.
func (s *spaceshipProvider) Delete(ctx context.Context, zone string, records []Record) error {
	if len(records) == 0 {
		return fmt.Errorf("provider %q: no records given", s.name)
	}

	zone = s.resolveZone(zone)

	items := make([]spaceshipRecord, 0, len(records))
	for _, record := range records {
		items = append(items, toSpaceship(record))
	}

	return s.deleteRecords(ctx, zone, items)
}

// deleteRecords issues the delete call. Spaceship takes a bare JSON array
// here, not an object with an items key - unlike the save endpoint.
func (s *spaceshipProvider) deleteRecords(ctx context.Context, zone string, items []spaceshipRecord) error {
	if len(items) == 0 {
		return nil
	}

	if err := s.do(ctx, http.MethodDelete, "/dns/records/"+url.PathEscape(zone), items, nil); err != nil {
		return fmt.Errorf("provider %q: delete %d record(s) from zone %q: %w", s.name, len(items), zone, err)
	}

	return nil
}

// Verify implements Verifier by reading the first page of the zone.
func (s *spaceshipProvider) Verify(ctx context.Context, zone string) error {
	zone = s.resolveZone(zone)

	path := fmt.Sprintf("/dns/records/%s?take=1&skip=0", url.PathEscape(zone))

	var page spaceshipPage
	if err := s.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return fmt.Errorf("provider %q: could not read zone %q: %w", s.name, zone, err)
	}

	return nil
}

// spaceshipPage is one page of the record listing.
type spaceshipPage struct {
	Items []spaceshipRecord `json:"items"`
	Total int               `json:"total"`
}

// list reads every record in a zone, following the pagination.
func (s *spaceshipProvider) list(ctx context.Context, zone string) ([]spaceshipRecord, error) {
	var (
		all  []spaceshipRecord
		skip int
	)

	for page := 0; page < spaceshipMaxPages; page++ {
		path := fmt.Sprintf("/dns/records/%s?take=%d&skip=%d",
			url.PathEscape(zone), spaceshipPageSize, skip)

		var decoded spaceshipPage
		if err := s.do(ctx, http.MethodGet, path, nil, &decoded); err != nil {
			return nil, fmt.Errorf("provider %q: read zone %q: %w", s.name, zone, err)
		}

		all = append(all, decoded.Items...)

		// An empty page ends the listing regardless of what total claims,
		// which is what stops a wrong total from looping.
		if len(decoded.Items) == 0 || len(all) >= decoded.Total {
			return all, nil
		}

		skip += len(decoded.Items)
	}

	return nil, fmt.Errorf(
		"provider %q: zone %q did not finish listing after %d pages of %d",
		s.name, zone, spaceshipMaxPages, spaceshipPageSize,
	)
}

// resolveZone falls back to the instance's configured zone.
func (s *spaceshipProvider) resolveZone(zone string) string {
	if zone == "" {
		return s.zone
	}

	return zone
}

// do issues one API call.
func (s *spaceshipProvider) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}

		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.endpoint+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("X-API-Key", s.key)
	req.Header.Set("X-API-Secret", s.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("call %s %s: %w", method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return s.apiError(resp)
	}

	// The save and delete endpoints answer 204, so there is nothing to decode.
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response from %s %s: %w", method, path, err)
	}

	return nil
}

// apiError renders a non-2xx response.
//
// The response body is included because Spaceship's validation messages name
// the offending record, which is the difference between "400 Bad Request" and
// a message an operator can act on. The credentials are in headers, not the
// body, so nothing here leaks them.
func (s *spaceshipProvider) apiError(resp *http.Response) error {
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, maxSpaceshipErrorBytes))

	message := "spaceship API returned " + resp.Status

	// Spaceship reports errors as {"detail": "...", "data": [...]}; falling
	// back to the raw body covers anything else, including a proxy's error
	// page.
	var structured struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(payload, &structured); err == nil && structured.Detail != "" {
		message += ": " + structured.Detail
	} else if trimmed := strings.TrimSpace(string(payload)); trimmed != "" {
		message += ": " + trimmed
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		message += " (check the API key and secret, and that the key has the dnsrecords:write permission)"
	}

	return &APIError{Status: resp.StatusCode, Message: message}
}

// APIError is a provider API failure carrying the HTTP status, so a caller can
// distinguish "credentials rejected" from "provider is down" - the former is
// permanent and should not be retried indefinitely.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

// Permanent reports whether retrying could plausibly help. A rejected
// credential or a malformed record will fail identically every time, and
// retrying it just delays the operator noticing.
func (e *APIError) Permanent() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}
