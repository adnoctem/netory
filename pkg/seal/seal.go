// Package seal is authenticated encryption for values netory stores somewhere
// it does not control.
//
// It exists because three places needed the same thing: pivot's backend
// credentials and cached responses in Valkey, which has no encryption at rest,
// and protean's and signpost's backups, which are files that leave the host.
// Writing AES-GCM three times is writing it twice too many - not because the
// code is hard, but because the parts that are easy to get subtly wrong (the
// nonce, what the tag covers, what a version byte is for) should be got right
// once and read once.
//
// # The format
//
//	magic[6] | version[1] | flags[1] | nonce[12] | ciphertext+tag
//
// The header is the AAD, so the magic, the version, the flags and the nonce
// are all covered by the tag. That is the detail worth stating: without it the
// flags byte is attacker-flippable, and a sealed value could be presented as
// an unsealed one.
//
// A magic and a version rather than a bare ciphertext, so a value found years
// later identifies itself and a format change is detectable instead of being
// read as corruption - or, worse, as a wrong key, which is the single most
// alarming and least informative thing a decryption failure can say.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// MagicLen is the length of a format magic.
const MagicLen = 6

// Version is the format version this package writes.
//
// Checked on open, so a value written by a newer build fails with "unknown
// format version" rather than with a decryption error that looks like a wrong
// key.
const Version uint8 = 1

// NonceLen is AES-GCM's standard nonce length.
const NonceLen = 12

// HeaderLen is magic + version + flags + nonce.
const HeaderLen = MagicLen + 1 + 1 + NonceLen

// FlagSealed marks a payload as encrypted.
//
// A flag rather than two formats, because some callers store both kinds under
// one key space: pivot's cache seals the entries of routes marked encrypt and
// stores the rest in the clear, and one reader has to handle both.
const FlagSealed uint8 = 1 << 0

// Sentinel errors.
var (
	// ErrNotSealed is returned for bytes that are not this format at all.
	ErrNotSealed = errors.New("seal: the value is not a sealed value")

	// ErrVersion is returned for a value from a newer format version.
	ErrVersion = errors.New("seal: the value was written in a newer format")

	// ErrOpen is returned when a sealed value does not decrypt. It means the
	// key is wrong or the bytes were altered, and the two are deliberately
	// indistinguishable - that is what an authenticated cipher guarantees.
	ErrOpen = errors.New("seal: the value could not be decrypted")

	// ErrNoKey is returned when sealing or opening is attempted without a
	// key.
	ErrNoKey = errors.New("seal: no key is configured")
)

// Sealer seals and opens values under one key and one format magic.
//
// The zero value is not usable; a Sealer built with no key can still carry
// unsealed values, which is what lets a caller with encryption switched off
// read and write through the same code path.
type Sealer struct {
	magic [MagicLen]byte
	gcm   cipher.AEAD
}

// New returns a Sealer for a magic and a key.
//
// The magic must be exactly MagicLen bytes and identifies the caller's format,
// so one caller cannot open another's values by accident: a cache entry handed
// to the backup reader fails as "not a sealed value" rather than as a
// decryption error.
//
// A nil or empty key returns a Sealer that cannot seal. That is not an error,
// because a caller whose encryption is optional - pivot's per-route cache flag
// - needs one object for both cases, and asking to seal without a key is then
// ErrNoKey at the point of the request rather than at construction.
func New(magic string, key []byte) (*Sealer, error) {
	if len(magic) != MagicLen {
		return nil, fmt.Errorf("seal: the magic must be %d bytes, got %q", MagicLen, magic)
	}

	sealer := &Sealer{magic: [MagicLen]byte([]byte(magic))}

	if len(key) == 0 {
		return sealer, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: build the cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: build AES-GCM: %w", err)
	}

	sealer.gcm = gcm

	return sealer, nil
}

// CanSeal reports whether the Sealer holds a key.
func (s *Sealer) CanSeal() bool { return s.gcm != nil }

// Seal encrypts a payload.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	if !s.CanSeal() {
		return nil, ErrNoKey
	}

	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: generate a nonce: %w", err)
	}

	// A random nonce per value rather than a counter. A counter would be
	// smaller and would need state that survives restarts and is not shared
	// between replicas - and a repeated nonce under one key is the failure
	// mode GCM does not survive.
	header := s.header(FlagSealed, nonce)

	return s.gcm.Seal(header, nonce, plaintext, header), nil
}

// Wrap stores a payload unsealed, in the same framing.
//
// The point is that one reader handles both: a caller can turn encryption on
// for some values and not others without the reader needing to know which it
// is looking at.
func (s *Sealer) Wrap(plaintext []byte) []byte {
	header := s.header(0, nil)

	return append(header, plaintext...)
}

// SealOr seals when sealed is true and wraps otherwise.
func (s *Sealer) SealOr(plaintext []byte, sealed bool) ([]byte, error) {
	if !sealed {
		return s.Wrap(plaintext), nil
	}

	return s.Seal(plaintext)
}

// header builds the framing. A nil nonce writes zeroes, which is correct for
// an unsealed value: nothing reads it.
func (s *Sealer) header(flags uint8, nonce []byte) []byte {
	header := make([]byte, 0, HeaderLen)
	header = append(header, s.magic[:]...)
	header = append(header, Version, flags)

	if nonce == nil {
		return append(header, make([]byte, NonceLen)...)
	}

	return append(header, nonce...)
}

// Open reads a value, decrypting it when it is sealed.
//
// The second result reports whether the value was sealed, which a caller may
// want to check: pivot refuses to serve a cached entry that should have been
// encrypted and was not, because the flag having been off is exactly the
// misconfiguration §7.3 warns about.
func (s *Sealer) Open(stored []byte) (plaintext []byte, wasSealed bool, err error) {
	if len(stored) < HeaderLen {
		return nil, false, ErrNotSealed
	}

	if [MagicLen]byte(stored[:MagicLen]) != s.magic {
		return nil, false, ErrNotSealed
	}

	version := stored[MagicLen]
	if version != Version {
		return nil, false, fmt.Errorf(
			"%w: version %d, this build writes %d", ErrVersion, version, Version)
	}

	flags := stored[MagicLen+1]
	nonce := stored[MagicLen+2 : HeaderLen]
	payload := stored[HeaderLen:]

	if flags&FlagSealed == 0 {
		// Copied rather than aliased: the caller keeps the result and the
		// stored slice may be reused by whatever produced it.
		out := make([]byte, len(payload))
		copy(out, payload)

		return out, false, nil
	}

	if !s.CanSeal() {
		return nil, true, ErrNoKey
	}

	opened, err := s.gcm.Open(nil, nonce, payload, stored[:HeaderLen])
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrOpen, err)
	}

	return opened, true, nil
}

// ErrNotEncrypted is returned by OpenSealed for a value that was stored
// unsealed.
var ErrNotEncrypted = errors.New("seal: the value was not encrypted")

// OpenSealed opens a value and refuses one that was not sealed.
//
// This is the call for anything that must always be encrypted - pivot's
// backend credentials - and it exists because the alternative is remembering
// to check Open's second result. An unsealed payload is, by definition,
// unauthenticated: its framing carries no tag, so clearing the sealed flag on
// a sealed value makes Open take the unsealed path and hand back ciphertext as
// though it were plaintext. That is not an escalation on its own, since anyone
// who can rewrite the flag can write a whole fresh unsealed value instead -
// unsealed storage is trusted exactly as far as the store is. What it does
// mean is that "this must have been encrypted" has to be checkable, and a
// method is a better place for that than a convention.
func (s *Sealer) OpenSealed(stored []byte) ([]byte, error) {
	plaintext, wasSealed, err := s.Open(stored)
	if err != nil {
		return nil, err
	}

	if !wasSealed {
		return nil, ErrNotEncrypted
	}

	return plaintext, nil
}

// IsSealed reports whether stored carries this Sealer's magic and its sealed
// flag, without needing a key.
//
// For an operator-facing check - "is this value encrypted" - that must work on
// a build whose key is not configured.
func (s *Sealer) IsSealed(stored []byte) bool {
	if len(stored) < HeaderLen {
		return false
	}

	if [MagicLen]byte(stored[:MagicLen]) != s.magic {
		return false
	}

	return stored[MagicLen+1]&FlagSealed != 0
}
