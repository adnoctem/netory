package secret_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/secret"
)

func TestGenerateProducesAnAcceptableSecret(t *testing.T) {
	asrt := assert.New(t)

	seen := map[string]struct{}{}
	for range 32 {
		raw, err := secret.Generate()
		require.NoError(t, err)

		_, dup := seen[raw]
		asrt.False(dup, "Generate must not repeat itself")
		seen[raw] = struct{}{}

		s, err := secret.Parse(raw)
		asrt.NoError(err, "a generated secret must pass Parse: %q", raw)
		asrt.NotNil(s)

		// Raw URL base64 so the value needs no quoting in an environment
		// variable, a URL or a shell.
		asrt.NotContains(raw, "+")
		asrt.NotContains(raw, "/")
		asrt.NotContains(raw, "=")
	}
}

func TestParseAcceptsEveryEncodingOfEnoughEntropy(t *testing.T) {
	asrt := assert.New(t)

	material := randomMaterial(t)

	for name, raw := range map[string]string{
		"raw bytes":      string(material),
		"hex":            hex.EncodeToString(material),
		"base64 std":     base64.StdEncoding.EncodeToString(material),
		"base64 raw URL": base64.RawURLEncoding.EncodeToString(material),
	} {
		s, err := secret.Parse(raw)
		asrt.NoError(err, name)

		if asrt.NotNil(s, name) {
			// Every encoding of the same material must derive the same key, or
			// re-encoding a secret during a deployment change would silently
			// make the database unreadable.
			got, err := s.DeriveEncryptionKey("protean/kv-encryption")
			asrt.NoError(err, name)
			asrt.Len(got, 32, name)
		}
	}
}

// All four encodings of one secret must derive identical keys.
func TestEncodingDoesNotChangeTheDerivedKey(t *testing.T) {
	asrt := assert.New(t)

	material := randomMaterial(t)

	var keys [][]byte
	for _, raw := range []string{
		string(material),
		hex.EncodeToString(material),
		base64.StdEncoding.EncodeToString(material),
		base64.RawURLEncoding.EncodeToString(material),
	} {
		s, err := secret.Parse(raw)
		require.NoError(t, err)

		k, err := s.Derive("protean/kv-encryption", 32)
		require.NoError(t, err)
		keys = append(keys, k)
	}

	for i := 1; i < len(keys); i++ {
		asrt.Equal(keys[0], keys[i], "encoding %d derived a different key", i)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	asrt := assert.New(t)

	for _, raw := range []string{"", " ", "\t\n  "} {
		_, err := secret.Parse(raw)
		asrt.ErrorIs(err, secret.ErrEmpty, "%q", raw)
		asrt.Contains(err.Error(), "secret generate", "the error must tell the operator how to fix it")
	}
}

// A 32-character hex string carries 16 bytes of entropy, not 32. Accepting it
// at face value would halve the security level of every derived key, so the
// length requirement is measured after decoding.
func TestParseRejectsShortSecretsAfterDecoding(t *testing.T) {
	asrt := assert.New(t)

	sixteen := randomMaterial(t)[:16]

	for name, raw := range map[string]string{
		"16 raw bytes":     string(sixteen),
		"16 bytes as hex":  hex.EncodeToString(sixteen), // 32 characters
		"16 bytes base64":  base64.RawURLEncoding.EncodeToString(sixteen),
		"short passphrase": "correct horse battery staple",
	} {
		_, err := secret.Parse(raw)
		asrt.ErrorIs(err, secret.ErrTooShort, "%s (%q)", name, raw)
	}

	// The boundary itself is accepted.
	thirtyTwo := randomMaterial(t)
	require.Len(t, thirtyTwo, secret.MinSecretBytes)
	_, err := secret.Parse(string(thirtyTwo))
	asrt.NoError(err)
}

func TestParseRejectsOversizedInput(t *testing.T) {
	asrt := assert.New(t)

	_, err := secret.Parse(strings.Repeat("a", secret.MaxSecretBytes+1))
	asrt.ErrorIs(err, secret.ErrTooLong)
	asrt.Contains(err.Error(), "path", "the likely cause is a path or a whole file, so say so")
}

// The placeholder that was never replaced is the realistic failure, and it is
// long enough to pass a pure length check.
func TestParseRejectsLowEntropyPlaceholders(t *testing.T) {
	asrt := assert.New(t)

	for name, raw := range map[string]string{
		"single character": strings.Repeat("a", 64),
		"changeme":         strings.Repeat("changeme", 8),
		"zero bytes":       string(make([]byte, 64)),
		"two characters":   strings.Repeat("ab", 32),
	} {
		_, err := secret.Parse(raw)
		asrt.ErrorIs(err, secret.ErrLowEntropy, "%s (%q)", name, raw)
	}
}

// Different info labels must produce computationally independent keys, which is
// the property that stops a leaked webhook signing key from being the database
// key as well.
func TestDeriveSeparatesPurposes(t *testing.T) {
	asrt := assert.New(t)

	raw, err := secret.Generate()
	require.NoError(t, err)

	s, err := secret.Parse(raw)
	require.NoError(t, err)

	labels := []string{
		"protean/kv-encryption",
		"protean/webhook-signing",
		"signpost/kv-encryption",
		"pivot/credential-encryption",
		"pivot/cache-encryption",
	}

	keys := map[string][]byte{}
	for _, label := range labels {
		k, err := s.Derive(label, 32)
		require.NoError(t, err, label)
		keys[label] = k
	}

	for i, a := range labels {
		for _, b := range labels[i+1:] {
			asrt.NotEqual(keys[a], keys[b], "%q and %q derived the same key", a, b)
		}
	}
}

// Derivation must be deterministic, or a restart would lose the database.
func TestDeriveIsDeterministic(t *testing.T) {
	asrt := assert.New(t)

	raw, err := secret.Generate()
	require.NoError(t, err)

	first, err := secret.Parse(raw)
	require.NoError(t, err)

	second, err := secret.Parse(raw)
	require.NoError(t, err)

	a, err := first.Derive("protean/kv-encryption", 32)
	require.NoError(t, err)

	b, err := second.Derive("protean/kv-encryption", 32)
	require.NoError(t, err)

	asrt.Equal(a, b, "the same secret and label must always derive the same key")
}

func TestDeriveLengths(t *testing.T) {
	asrt := assert.New(t)

	raw, err := secret.Generate()
	require.NoError(t, err)

	s, err := secret.Parse(raw)
	require.NoError(t, err)

	// Badger accepts 16, 24 and 32-byte keys, and HKDF can emit far more.
	for _, length := range []int{1, 16, 24, 32, 64, 255} {
		k, err := s.Derive("protean/kv-encryption", length)
		asrt.NoError(err, "%d", length)
		asrt.Len(k, length, "%d", length)
	}

	// The database key is always AES-256, never a slice of the raw secret.
	enc, err := s.DeriveEncryptionKey("protean/kv-encryption")
	asrt.NoError(err)
	asrt.Len(enc, 32)

	hmacKey, err := s.DeriveHMACKey("protean/webhook-signing")
	asrt.NoError(err)
	asrt.Len(hmacKey, 32)
	asrt.NotEqual(enc, hmacKey)
}

func TestDeriveRejectsBadArguments(t *testing.T) {
	asrt := assert.New(t)

	raw, err := secret.Generate()
	require.NoError(t, err)

	s, err := secret.Parse(raw)
	require.NoError(t, err)

	// An empty label would silently collapse every purpose onto one key, so it
	// has no default.
	_, err = s.Derive("", 32)
	asrt.Error(err)
	asrt.Contains(err.Error(), "info label")

	for _, length := range []int{0, -1} {
		_, err = s.Derive("protean/kv-encryption", length)
		asrt.Error(err, "%d", length)
	}
}

// The raw secret must not be reachable through a format verb, because the
// realistic leak is a struct dump of the application config into a log.
func TestSecretIsRedactedWhenFormatted(t *testing.T) {
	asrt := assert.New(t)

	material := string(randomMaterial(t))
	s, err := secret.Parse(material)
	require.NoError(t, err)

	type appConfig struct {
		Name   string
		Secret *secret.Secret
	}
	cfg := appConfig{Name: "protean", Secret: s}

	// The verbs are iterated rather than written as literal format strings so
	// that each one is genuinely exercised. A literal fmt.Sprintf("%s", s) is
	// rewritten to s.String() by staticcheck's advice, which would stop the
	// test from checking the %s path at all.
	var rendered []string
	for _, verb := range []string{"%v", "%s", "%q", "%#v", "%+v"} {
		rendered = append(rendered, fmt.Sprintf(verb, s), fmt.Sprintf(verb, cfg))
	}
	rendered = append(rendered, s.String(), s.GoString())

	for _, rendered := range rendered {
		asrt.NotContains(rendered, material, "the raw secret reached a formatted string: %s", rendered)
		asrt.Contains(rendered, "redacted")
	}
}

// There is no accessor for the raw material, by design: the mistake worth
// preventing is handing it to Badger directly as an encryption key.
func TestSecretExposesNoRawAccessor(t *testing.T) {
	asrt := assert.New(t)

	// A compile-time assertion would be better, but the absence of a method
	// cannot be asserted that way. This documents the intent next to the
	// tests that depend on it.
	raw, err := secret.Generate()
	require.NoError(t, err)

	s, err := secret.Parse(raw)
	require.NoError(t, err)

	asrt.NotContains(fmt.Sprintf("%#v", s), raw)
}

// randomMaterial returns MinSecretBytes of random bytes that are not
// themselves a valid hex or base64 string, so a test can exercise the raw-byte
// path without colliding with the encoding ambiguity documented on Parse.
func randomMaterial(t *testing.T) []byte {
	t.Helper()

	for range 64 {
		buf := make([]byte, secret.MinSecretBytes)
		_, err := rand.Read(buf)
		require.NoError(t, err)

		// Reject anything that would be read as an encoding rather than as
		// raw bytes, and anything Parse's whitespace trimming would shorten.
		// For random input these effectively never trigger; the loop is here
		// so the test cannot flake.
		s := string(buf)
		if strings.TrimSpace(s) != s {
			continue
		}
		if _, err := hex.DecodeString(s); err == nil {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(s); err == nil {
			continue
		}
		if _, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			continue
		}

		return buf
	}

	t.Fatal("could not draw random material that is not also a valid encoding")

	return nil
}

// An input that is both 32 raw bytes and the hex encoding of 16 is read as
// encoded, and therefore rejected. This pins the documented resolution of the
// ambiguity: the alternative would silently accept a 16-byte secret.
func TestParseResolvesTheEncodingAmbiguityTowardsRejection(t *testing.T) {
	asrt := assert.New(t)

	ambiguous := "0123456789abcdef0123456789abcdef"
	require.Len(t, ambiguous, secret.MinSecretBytes)

	_, err := secret.Parse(ambiguous)
	asrt.ErrorIs(err, secret.ErrTooShort,
		"an input that is also valid hex must be read as hex, not as 32 raw bytes")
	asrt.Contains(err.Error(), "hex decoding")
}

// Generate's output has exactly one valid reading, so it can never be caught
// by the ambiguity above.
func TestGeneratedSecretsAreUnambiguous(t *testing.T) {
	asrt := assert.New(t)

	for range 64 {
		raw, err := secret.Generate()
		require.NoError(t, err)

		// 43 characters: an odd length, which no hex string has, and not a
		// multiple of four, which standard base64 requires.
		asrt.Len(raw, 43)

		_, hexErr := hex.DecodeString(raw)
		asrt.Error(hexErr, "a generated secret must not also be valid hex: %q", raw)

		_, stdErr := base64.StdEncoding.DecodeString(raw)
		asrt.Error(stdErr, "a generated secret must not also be valid standard base64: %q", raw)

		// It must of course decode as what it is.
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		asrt.NoError(err)
		asrt.Len(decoded, secret.GeneratedSecretBytes)
	}
}
