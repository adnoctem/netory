package seal_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/seal"
)

const magic = "NTRYTT"

func key(t *testing.T) []byte {
	t.Helper()

	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}

	return k
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)
	require.True(t, sealer.CanSeal())

	plaintext := []byte("a credential with \x00 a null and invalid \xff utf-8")

	sealed, err := sealer.Seal(plaintext)
	require.NoError(t, err)

	assert.NotContains(t, string(sealed), "credential", "the payload must not be readable")
	assert.True(t, sealer.IsSealed(sealed))

	opened, wasSealed, err := sealer.Open(sealed)
	require.NoError(t, err)
	assert.True(t, wasSealed)
	assert.Equal(t, plaintext, opened)
}

// One reader has to handle both kinds, which is what lets pivot's cache seal
// the routes marked encrypt and store the rest in the clear.
func TestWrapAndOpenUnsealed(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, nil)
	require.NoError(t, err)
	require.False(t, sealer.CanSeal())

	plaintext := []byte("not a secret")
	wrapped := sealer.Wrap(plaintext)

	assert.False(t, sealer.IsSealed(wrapped))

	opened, wasSealed, err := sealer.Open(wrapped)
	require.NoError(t, err)
	assert.False(t, wasSealed)
	assert.Equal(t, plaintext, opened)
}

func TestSealOr(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	plaintext := []byte("value")

	for _, sealed := range []bool{true, false} {
		stored, err := sealer.SealOr(plaintext, sealed)
		require.NoError(t, err)

		assert.Equal(t, sealed, sealer.IsSealed(stored))

		opened, wasSealed, err := sealer.Open(stored)
		require.NoError(t, err)
		assert.Equal(t, sealed, wasSealed)
		assert.Equal(t, plaintext, opened)
	}
}

// Sealing without a key is an error at the point of the request rather than at
// construction, because a caller whose encryption is optional needs one object
// for both cases.
func TestSealWithoutAKey(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, nil)
	require.NoError(t, err)

	_, err = sealer.Seal([]byte("x"))
	assert.ErrorIs(t, err, seal.ErrNoKey)

	_, err = sealer.SealOr([]byte("x"), true)
	assert.ErrorIs(t, err, seal.ErrNoKey)
}

func TestOpenSealedWithoutAKey(t *testing.T) {
	t.Parallel()

	withKey, err := seal.New(magic, key(t))
	require.NoError(t, err)

	sealed, err := withKey.Seal([]byte("x"))
	require.NoError(t, err)

	withoutKey, err := seal.New(magic, nil)
	require.NoError(t, err)

	// The flag is readable without a key, so the caller is told the value is
	// sealed rather than being told it is corrupt.
	assert.True(t, withoutKey.IsSealed(sealed))

	_, wasSealed, err := withoutKey.Open(sealed)
	assert.ErrorIs(t, err, seal.ErrNoKey)
	assert.True(t, wasSealed)
}

// The header is the AAD, so none of it can be altered. Without that the flags
// byte would be attacker-flippable and a sealed value could be presented as an
// unsealed one.
func TestTamperEvidence(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	sealed, err := sealer.Seal([]byte("the secret"))
	require.NoError(t, err)

	for name, offset := range map[string]int{
		"the version":    seal.MagicLen,
		"the nonce":      seal.MagicLen + 2,
		"the ciphertext": seal.HeaderLen,
		"the tag":        len(sealed) - 1,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tampered := bytes.Clone(sealed)
			tampered[offset] ^= 0xff

			_, _, err := sealer.Open(tampered)
			assert.Error(t, err, "altering %s must be detected", name)
		})
	}

	// Clearing the sealed flag is the one alteration the framing cannot
	// detect, because an unsealed payload carries no tag to verify against.
	// What comes back is ciphertext rather than the plaintext, and the caller
	// is told the value was not sealed - which is why anything that must
	// always be encrypted uses OpenSealed rather than remembering to check.
	t.Run("clearing the sealed flag is reported, not decrypted", func(t *testing.T) {
		t.Parallel()

		tampered := bytes.Clone(sealed)
		tampered[seal.MagicLen+1] &= ^seal.FlagSealed

		opened, wasSealed, err := sealer.Open(tampered)
		require.NoError(t, err, "the framing still parses")
		assert.False(t, wasSealed)
		assert.NotContains(t, string(opened), "the secret")

		_, err = sealer.OpenSealed(tampered)
		assert.ErrorIs(t, err, seal.ErrNotEncrypted,
			"a caller that requires encryption must be told it did not get it")
	})
}

// OpenSealed is the call for anything that must always be encrypted, so that
// "this must have been sealed" is checkable rather than remembered.
func TestOpenSealed(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	sealed, err := sealer.Seal([]byte("a credential"))
	require.NoError(t, err)

	opened, err := sealer.OpenSealed(sealed)
	require.NoError(t, err)
	assert.Equal(t, []byte("a credential"), opened)

	_, err = sealer.OpenSealed(sealer.Wrap([]byte("in the clear")))
	assert.ErrorIs(t, err, seal.ErrNotEncrypted)
}

// One caller must not open another's values by accident: a cache entry handed
// to the backup reader is "not a sealed value", not a decryption error.
func TestMagicSeparatesCallers(t *testing.T) {
	t.Parallel()

	first, err := seal.New("NTRYAA", key(t))
	require.NoError(t, err)

	second, err := seal.New("NTRYBB", key(t))
	require.NoError(t, err)

	sealed, err := first.Seal([]byte("x"))
	require.NoError(t, err)

	_, _, err = second.Open(sealed)
	assert.ErrorIs(t, err, seal.ErrNotSealed)
	assert.False(t, second.IsSealed(sealed))
}

// A value from a newer build must fail as a version problem rather than as a
// decryption error that looks like a wrong key.
func TestVersionMismatch(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	sealed, err := sealer.Seal([]byte("x"))
	require.NoError(t, err)

	sealed[seal.MagicLen] = seal.Version + 1

	_, _, err = sealer.Open(sealed)
	assert.ErrorIs(t, err, seal.ErrVersion)
}

func TestOpenRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	for name, stored := range map[string][]byte{
		"empty":       {},
		"too short":   []byte("NTRYTT"),
		"wrong magic": append([]byte("OTHERX"), make([]byte, seal.HeaderLen)...),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := sealer.Open(stored)
			assert.ErrorIs(t, err, seal.ErrNotSealed)
		})
	}
}

func TestNewValidatesTheMagic(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "SHORT", "TOOLONGXX"} {
		_, err := seal.New(bad, key(t))
		assert.Error(t, err, "magic %q", bad)
	}

	_, err := seal.New(magic, []byte("not-a-valid-aes-key-length"))
	assert.Error(t, err)
}

// A repeated nonce under one key is the failure mode GCM does not survive, so
// two seals of one plaintext must differ.
func TestNoncesDiffer(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	seen := map[string]bool{}

	for range 100 {
		sealed, err := sealer.Seal([]byte("the same plaintext"))
		require.NoError(t, err)

		nonce := string(sealed[seal.MagicLen+2 : seal.HeaderLen])
		require.False(t, seen[nonce], "a nonce repeated")
		seen[nonce] = true
	}
}

func TestEmptyPayload(t *testing.T) {
	t.Parallel()

	sealer, err := seal.New(magic, key(t))
	require.NoError(t, err)

	sealed, err := sealer.Seal(nil)
	require.NoError(t, err)

	opened, wasSealed, err := sealer.Open(sealed)
	require.NoError(t, err)
	assert.True(t, wasSealed)
	assert.Empty(t, opened)
}
