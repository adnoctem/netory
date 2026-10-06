// Package secret validates a service's single high-entropy secret and derives
// every working key from it.
//
// The model is Symfony's APP_SECRET: one string reaches the process by
// whatever means the operator prefers - environment variable, file, systemd
// credential, container secret - and everything cryptographic is derived from
// it. protean reads PROTEAN_SECRET, signpost SIGNPOST_SECRET and pivot
// PIVOT_SECRET, and all three use this package to do it.
//
// # Why HKDF and not a password hash
//
// HKDF is a key-derivation function for input that is already uniformly
// random; it is deliberately fast. That is only safe because this package
// *requires* the input to be random: a secret shorter than MinSecretBytes
// after decoding is rejected outright, so there is no low-entropy,
// human-chosen secret for an attacker to search. crypto/pbkdf2 or Argon2 would
// buy nothing against a 32-byte random value, and the rejection of short
// secrets is what makes the cheaper derivation defensible rather than merely
// convenient.
//
// # The encoding ambiguity, and which way it is resolved
//
// The length requirement is measured after decoding, because a 32-character
// hex string carries 16 bytes of entropy rather than 32 and accepting it at
// face value would halve the security level of every derived key. That makes
// some inputs genuinely ambiguous: "0123456789abcdef0123456789abcdef" is both
// 32 raw bytes and the hex encoding of 16, and nothing in the string says
// which was meant.
//
// Such inputs are read as encoded, and therefore rejected as too short. The
// trade is deliberate. Reading them as raw would silently accept a 16-byte
// secret; reading them as encoded can only reject a 32-byte raw secret drawn
// entirely from the 16 hex characters, which no random secret is - the odds
// are (16/256)^32 - and which a hand-written placeholder very much is. The
// output of Generate is immune either way: it is 43 characters of raw URL
// base64, an odd length no hex string can have and not a multiple of four, so
// it has exactly one valid reading.
//
// # Why the raw secret never leaves this package
//
// A Secret hands out derived keys and nothing else. Passing the raw secret
// around invites exactly the mistake that matters here - using it directly as
// the Badger encryption key, which accepts 16, 24 or 32 bytes and would
// silently take a truncated or wrong-length slice of it. Derive returns the
// length the caller asked for, from a key that is cryptographically
// independent of every other purpose's key.
package secret

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// MinSecretBytes is the smallest accepted secret, measured after decoding.
	// 32 bytes is 256 bits, which is the security level of everything derived
	// from it: AES-256 for the database and HMAC-SHA256 for webhook
	// signatures. A shorter secret would make the derivation the weakest link.
	MinSecretBytes = 32

	// GeneratedSecretBytes is the size of a secret from Generate.
	GeneratedSecretBytes = 32

	// MaxSecretBytes bounds the accepted input. HKDF accepts input keying
	// material of any length, so this is not a cryptographic limit - it is a
	// guard against a misconfiguration that points the secret at a large file
	// and then reports a confusing failure much later.
	MaxSecretBytes = 4096
)

// Sentinel errors. Every one carries a hint in its message, because the
// operator reading it is configuring a service, not debugging this package.
var (
	// ErrEmpty is returned when the secret is empty or whitespace only.
	ErrEmpty = errors.New("secret: is empty")

	// ErrTooShort is returned when the decoded secret is shorter than
	// MinSecretBytes.
	ErrTooShort = errors.New("secret: is too short")

	// ErrTooLong is returned when the input exceeds MaxSecretBytes.
	ErrTooLong = errors.New("secret: is too long")

	// ErrLowEntropy is returned when the secret decodes to the required length
	// but is obviously not random.
	ErrLowEntropy = errors.New("secret: has insufficient entropy")
)

// Secret is a validated service secret. It is immutable and safe for
// concurrent use.
//
// The raw material is unexported and there is no accessor, so a caller can
// only obtain purpose-bound derived keys.
type Secret struct {
	material []byte
}

// Generate produces a new secret suitable for PROTEAN_SECRET, SIGNPOST_SECRET
// or PIVOT_SECRET, as base64 (raw URL encoding, so it is safe in an
// environment variable, a URL and a shell without quoting).
func Generate() (string, error) {
	buf := make([]byte, GeneratedSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secret: read random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Parse validates raw and returns a Secret.
//
// The input may be raw bytes, hex, standard base64 or raw URL base64. Decoding
// is attempted because the entropy requirement is about the decoded value: a
// 32-character hex string carries 16 bytes of entropy, not 32, and accepting
// it at face value would halve the security level of every derived key without
// anyone noticing.
// Note that leading and trailing whitespace is trimmed. That is required for
// the file delivery path - a secret file written by `secret generate >` or by a
// secret manager normally ends in a newline, and a secret differing from the
// one that encrypted the database by a single byte makes it unreadable. The
// consequence is that raw *binary* material beginning or ending with a
// whitespace byte would be shortened; Generate produces base64 precisely so
// that the delivered value is text with no such edge.
func Parse(raw string) (*Secret, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: generate one with `secret generate`", ErrEmpty)
	}

	if len(trimmed) > MaxSecretBytes {
		return nil, fmt.Errorf(
			"%w: %d bytes, limit is %d - check that the secret is the value itself and not a path or a file's contents",
			ErrTooLong, len(trimmed), MaxSecretBytes,
		)
	}

	material, encoding := decode(trimmed)
	if len(material) < MinSecretBytes {
		return nil, fmt.Errorf(
			"%w: %d bytes after %s decoding, minimum is %d - generate one with `secret generate`",
			ErrTooShort, len(material), encoding, MinSecretBytes,
		)
	}

	if err := checkEntropy(material, encoding); err != nil {
		return nil, err
	}

	return &Secret{material: material}, nil
}

// decode returns the secret's bytes and the name of the encoding used.
//
// A secret is only treated as encoded when the decoding round-trips back to
// the original string. Without that check a raw 32-byte secret that happens to
// be valid hex would be decoded down to 16 bytes and rejected as too short.
func decode(s string) (material []byte, encoding string) {
	if b, err := hex.DecodeString(s); err == nil && hex.EncodeToString(b) == strings.ToLower(s) {
		return b, "hex"
	}

	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && base64.RawURLEncoding.EncodeToString(b) == s {
		return b, "base64"
	}

	if b, err := base64.StdEncoding.DecodeString(s); err == nil && base64.StdEncoding.EncodeToString(b) == s {
		return b, "base64"
	}

	return []byte(s), "no"
}

// checkEntropy rejects a secret that is long enough but plainly not random.
//
// This is a sanity check on configuration, not a statistical test: it catches
// the placeholder that was never replaced - "changeme" repeated to length, a
// run of one character, a secret of only a handful of distinct bytes. A real
// entropy estimate on 32 bytes is not meaningful, and anything stricter would
// reject legitimate random values.
func checkEntropy(material []byte, encoding string) error {
	distinct := map[byte]struct{}{}
	for _, b := range material {
		distinct[b] = struct{}{}
	}

	// 32 uniformly random bytes have ~28 distinct values on average, and the
	// chance of fewer than 8 is negligible. A deliberate placeholder almost
	// always has far fewer.
	const minDistinct = 8
	if len(distinct) < minDistinct {
		return fmt.Errorf(
			"%w: %d bytes after %s decoding but only %d distinct values - this looks like a placeholder rather than output of `secret generate`",
			ErrLowEntropy, len(material), encoding, len(distinct),
		)
	}

	return nil
}

// Derive returns length bytes of key material bound to info.
//
// info is a purpose label and must be unique per use, by convention
// "<service>/<purpose>" - "protean/kv-encryption", "signpost/webhook-signing",
// "pivot/cache-encryption". HKDF guarantees that keys derived under different
// labels are computationally independent, so compromising a webhook signing
// key tells an attacker nothing about the database key. Reusing a label for
// two purposes silently throws that guarantee away, which is why the label is
// a required argument with no default.
func (s *Secret) Derive(info string, length int) ([]byte, error) {
	if info == "" {
		return nil, errors.New("secret: Derive requires a non-empty info label, by convention \"<service>/<purpose>\"")
	}

	if length <= 0 {
		return nil, fmt.Errorf("secret: Derive length must be positive, got %d", length)
	}

	// A nil salt is correct here. HKDF's salt defends against input keying
	// material with structure or partial attacker knowledge; this secret is
	// required to be uniformly random, and the info label already separates
	// purposes. A per-service random salt would also have to be stored
	// somewhere, which turns one secret to manage into two.
	key, err := hkdf.Key(sha256.New, s.material, nil, info, length)
	if err != nil {
		return nil, fmt.Errorf("secret: derive %q: %w", info, err)
	}

	return key, nil
}

// DeriveEncryptionKey returns a 32-byte key for AES-256.
//
// Badger accepts a 16, 24 or 32-byte encryption key and will happily take a
// wrong-length slice of a raw secret. This exists so the database key is
// always AES-256 and always derived, and never the secret itself.
func (s *Secret) DeriveEncryptionKey(info string) ([]byte, error) {
	return s.Derive(info, 32)
}

// DeriveHMACKey returns a 32-byte key for HMAC-SHA256, matching the hash's
// block-size-appropriate key length for webhook signatures.
func (s *Secret) DeriveHMACKey(info string) ([]byte, error) {
	return s.Derive(info, 32)
}

// String redacts the secret so it cannot reach a log line through a %v, a
// struct dump or an error wrapping the app config.
func (s *Secret) String() string { return "secret.Secret(redacted)" }

// GoString redacts the secret under %#v as well, which is what a struct dump
// of an application's configuration actually uses.
func (s *Secret) GoString() string { return s.String() }
