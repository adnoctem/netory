package cache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/adnoctem/netory/pkg/seal"
)

// Magic identifies a pivot cache entry.
//
// Its own magic, distinct from every other sealed value in netory, so a cache
// entry handed to another reader fails as "not this format" rather than as a
// decryption error. pkg/seal carries the framing and the version byte; this
// package carries the entry encoding inside it.
const Magic = "NTRYCA"

// Sentinel errors.
var (
	// ErrNotAnEntry is returned for stored bytes that are not a cache entry.
	ErrNotAnEntry = errors.New("cache: the stored value is not a cache entry")

	// ErrUnsupportedVersion is returned for an entry from a newer pivot.
	//
	// This is the rolling-deployment case: two pivot versions share one Valkey
	// while a deployment rolls, and the older must not decode the newer one's
	// entries into nonsense. The Store turns it into a cache miss.
	ErrUnsupportedVersion = errors.New("cache: the entry was written in a newer format")

	// ErrUnseal is returned when an encrypted entry cannot be decrypted.
	ErrUnseal = errors.New("cache: the entry could not be decrypted")

	// ErrEncryptionUnavailable is returned when an encrypted entry is read
	// without a key, or an encrypted route is configured without one.
	ErrEncryptionUnavailable = errors.New("cache: no cache encryption key is configured")

	// ErrPlaintextEntry is returned when a route that requires encryption
	// reads an entry that was stored in the clear.
	//
	// §7.3's flag is set on routes whose responses can carry personal data, so
	// an entry stored before the flag was turned on must be discarded rather
	// than served - it is exactly the data the operator decided needed
	// protecting.
	ErrPlaintextEntry = errors.New("cache: the entry was stored unencrypted")
)

// Codec encodes and decodes cache entries, sealing them when a key is set.
//
// The key is per-instance rather than per-route: §7.3 makes encryption a
// per-route flag, not a per-route key, so an operator turning the flag on for
// a route needs no key management of their own.
type Codec struct {
	sealer *seal.Sealer
}

// NewCodec returns a codec. A nil or empty key means no encryption is
// available, and a route that asks for it fails loudly rather than storing a
// plaintext entry.
func NewCodec(key []byte) (*Codec, error) {
	sealer, err := seal.New(Magic, key)
	if err != nil {
		return nil, err
	}

	return &Codec{sealer: sealer}, nil
}

// CanEncrypt reports whether the codec holds a key.
func (c *Codec) CanEncrypt() bool { return c.sealer.CanSeal() }

// Encode renders an entry for storage, sealing it when encrypt is set.
//
// A route marked encrypt without a key available is an error rather than a
// plaintext write. §7.3's whole point is that the flag is set on routes whose
// responses can carry personal data, so silently storing one in the clear
// would break exactly the promise the flag was turned on to make.
func (c *Codec) Encode(entry Entry, encrypt bool) ([]byte, error) {
	if encrypt && !c.CanEncrypt() {
		return nil, ErrEncryptionUnavailable
	}

	stored, err := c.sealer.SealOr(marshal(entry), encrypt)
	if err != nil {
		return nil, fmt.Errorf("cache: encode an entry: %w", err)
	}

	return stored, nil
}

// Decode reads a stored entry.
//
// requireEncryption is the route's flag: an entry stored in the clear for a
// route that now requires encryption is refused rather than served, because it
// holds the data the operator decided needed protecting.
func (c *Codec) Decode(stored []byte, requireEncryption bool) (Entry, error) {
	plaintext, wasSealed, err := c.sealer.Open(stored)

	switch {
	case errors.Is(err, seal.ErrNotSealed):
		return Entry{}, ErrNotAnEntry
	case errors.Is(err, seal.ErrVersion):
		return Entry{}, fmt.Errorf("%w: %w", ErrUnsupportedVersion, err)
	case errors.Is(err, seal.ErrNoKey):
		return Entry{}, ErrEncryptionUnavailable
	case errors.Is(err, seal.ErrOpen):
		return Entry{}, fmt.Errorf("%w: %w", ErrUnseal, err)
	case err != nil:
		return Entry{}, fmt.Errorf("cache: decode an entry: %w", err)
	}

	if requireEncryption && !wasSealed {
		return Entry{}, ErrPlaintextEntry
	}

	return unmarshal(plaintext)
}

// marshal renders an entry as length-prefixed bytes.
//
// An explicit format rather than JSON, because the body is arbitrary bytes:
// base64 inside JSON would inflate every cached response by a third, and these
// live in somebody's Valkey memory.
func marshal(entry Entry) []byte {
	out := make([]byte, 0, 32+len(entry.Body))

	out = binary.AppendVarint(out, int64(entry.Status))
	out = binary.AppendVarint(out, entry.StoredAt.UnixMilli())

	names := make([]string, 0, len(entry.Header))
	for name := range entry.Header {
		names = append(names, name)
	}

	// Sorted so one entry has one encoding, which makes the format testable
	// by comparing bytes.
	sortStrings(names)

	out = binary.AppendUvarint(out, uint64(len(names)))

	for _, name := range names {
		values := entry.Header[name]

		out = appendString(out, name)
		out = binary.AppendUvarint(out, uint64(len(values)))

		for _, value := range values {
			out = appendString(out, value)
		}
	}

	return appendBytes(out, entry.Body)
}

// unmarshal reads an entry back.
func unmarshal(data []byte) (Entry, error) {
	status, n := binary.Varint(data)
	if n <= 0 {
		return Entry{}, ErrNotAnEntry
	}

	data = data[n:]

	storedAt, n := binary.Varint(data)
	if n <= 0 {
		return Entry{}, ErrNotAnEntry
	}

	data = data[n:]

	count, n := binary.Uvarint(data)
	if n <= 0 {
		return Entry{}, ErrNotAnEntry
	}

	data = data[n:]

	// Bounded because the count comes from the stored bytes: a corrupt or
	// hostile value would otherwise make this allocate whatever it says.
	const maxHeaders = 64
	if count > maxHeaders {
		return Entry{}, fmt.Errorf("%w: %d headers", ErrNotAnEntry, count)
	}

	header := make(http.Header, count)

	for range count {
		name, rest, err := takeString(data)
		if err != nil {
			return Entry{}, err
		}

		data = rest

		valueCount, n := binary.Uvarint(data)
		if n <= 0 || valueCount > maxHeaders {
			return Entry{}, ErrNotAnEntry
		}

		data = data[n:]

		for range valueCount {
			value, rest, err := takeString(data)
			if err != nil {
				return Entry{}, err
			}

			data = rest
			header.Add(name, value)
		}
	}

	body, rest, err := takeBytes(data)
	if err != nil {
		return Entry{}, err
	}

	if len(rest) != 0 {
		return Entry{}, fmt.Errorf("%w: %d trailing bytes", ErrNotAnEntry, len(rest))
	}

	return Entry{
		Status:   int(status),
		Header:   header,
		Body:     body,
		StoredAt: time.UnixMilli(storedAt).UTC(),
	}, nil
}

// appendString writes a length-prefixed string.
func appendString(out []byte, value string) []byte {
	out = binary.AppendUvarint(out, uint64(len(value)))

	return append(out, value...)
}

// appendBytes writes a length-prefixed byte slice.
func appendBytes(out []byte, value []byte) []byte {
	out = binary.AppendUvarint(out, uint64(len(value)))

	return append(out, value...)
}

// takeString reads a length-prefixed string.
func takeString(data []byte) (string, []byte, error) {
	value, rest, err := takeBytes(data)
	if err != nil {
		return "", nil, err
	}

	return string(value), rest, nil
}

// takeBytes reads a length-prefixed byte slice, checking the length against
// what is actually there rather than trusting it.
func takeBytes(data []byte) ([]byte, []byte, error) {
	length, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, nil, ErrNotAnEntry
	}

	data = data[n:]

	if length > uint64(len(data)) {
		return nil, nil, fmt.Errorf(
			"%w: a field claims %d bytes but %d remain", ErrNotAnEntry, length, len(data))
	}

	// Copied rather than aliased: the caller keeps the entry and the stored
	// slice may be reused by the store.
	out := make([]byte, length)
	copy(out, data[:length])

	return out, data[length:], nil
}

// sortStrings orders header names so one entry has one encoding, which makes
// the format testable by comparing bytes. An insertion sort because the slice
// is at most the length of cacheableHeaders.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
