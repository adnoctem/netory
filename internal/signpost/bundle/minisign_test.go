package bundle_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// jedisct1's published minisign public key, from minisign's own README.
//
// Embedded here rather than read from testdata on purpose: a test that read
// both the key and the fixture from the same directory would still pass if
// someone replaced both, which is exactly the substitution a signature is
// supposed to detect.
// This is a *public* key, published by minisign for verifying its own
// releases; gitleaks cannot tell one high-entropy string from another.
const minisignUpstreamKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3" //gitleaks:allow

// THE compatibility test. A real signature, produced by the actual minisign
// implementation, verified by this package.
//
// A self-consistent round-trip test is not enough: a signer and a verifier
// built on the same wrong understanding of the byte layout would agree with
// each other while rejecting - or wrongly accepting - every real signature.
// Only a genuine signature rules that out.
func TestVerifyRealMinisignSignature(t *testing.T) {
	asrt := assert.New(t)

	archive, err := os.ReadFile(filepath.Join("testdata", "minisign-0.12.tar.gz"))
	require.NoError(t, err)

	signature, err := os.ReadFile(filepath.Join("testdata", "minisign-0.12.tar.gz.minisig"))
	require.NoError(t, err)

	sig, err := bundle.VerifyBundle(minisignUpstreamKey, signature, archive)
	require.NoError(t, err, "a genuine minisign signature must verify")

	asrt.True(sig.Prehashed, "modern minisign prehashes, so the fixture must exercise that path")
	asrt.Contains(sig.TrustedComment, "minisign-0.12.tar.gz",
		"the trusted comment names the file, and is covered by the global signature")
	asrt.Contains(sig.TrustedComment, "timestamp:")
}

// The same fixture must be rejected the moment anything about it changes.
func TestRealSignatureRejectsTampering(t *testing.T) {
	asrt := assert.New(t)

	archive, err := os.ReadFile(filepath.Join("testdata", "minisign-0.12.tar.gz"))
	require.NoError(t, err)

	signature, err := os.ReadFile(filepath.Join("testdata", "minisign-0.12.tar.gz.minisig"))
	require.NoError(t, err)

	// A single flipped byte in the archive.
	tampered := make([]byte, len(archive))
	copy(tampered, archive)
	tampered[len(tampered)/2] ^= 0xff

	_, err = bundle.VerifyBundle(minisignUpstreamKey, signature, tampered)
	asrt.ErrorIs(err, bundle.ErrSignatureInvalid, "a modified archive must not verify")

	// A rewritten trusted comment. This is what the global signature is for:
	// signpost records the trusted comment in its audit log, so a comment that
	// could be changed freely would be a field an auditor should not rely on.
	rewritten := strings.Replace(string(signature),
		"file:minisign-0.12.tar.gz", "file:something-else.tar.gz", 1)
	require.NotEqual(t, string(signature), rewritten, "the replacement must have applied")

	_, err = bundle.VerifyBundle(minisignUpstreamKey, []byte(rewritten), archive)
	asrt.ErrorIs(err, bundle.ErrSignatureInvalid,
		"a rewritten trusted comment must not verify")

	// A different key.
	other, _, err := newMinisignKeypair(t)
	require.NoError(t, err)

	_, err = bundle.VerifyBundle(other, signature, archive)
	asrt.ErrorIs(err, bundle.ErrKeyMismatch, "a signature from another key must be rejected")
}

// newMinisignKeypair generates a keypair and returns the public key in
// minisign's encoding, so tests can sign their own fixtures.
func newMinisignKeypair(t *testing.T) (publicKey string, private ed25519.PrivateKey, err error) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}

	keyID := make([]byte, 8)
	if _, err := rand.Read(keyID); err != nil {
		return "", nil, err
	}

	blob := append([]byte{'E', 'd'}, keyID...)
	blob = append(blob, pub...)

	return base64.StdEncoding.EncodeToString(blob), priv, nil
}

// signMinisign produces a signature in minisign's format, for the cases a
// real fixture cannot cover - the legacy algorithm, and malformed variants.
func signMinisign(
	t *testing.T, publicKey string, private ed25519.PrivateKey, content []byte,
	prehashed bool, trustedComment string,
) []byte {
	t.Helper()

	blob, err := base64.StdEncoding.DecodeString(publicKey)
	require.NoError(t, err)
	keyID := blob[2:10]

	alg := []byte{'E', 'd'}
	message := content

	if prehashed {
		alg = []byte{'E', 'D'}
		digest := blake2b.Sum512(content)
		message = digest[:]
	}

	signature := ed25519.Sign(private, message)

	sigBlob := append(append([]byte{}, alg...), keyID...)
	sigBlob = append(sigBlob, signature...)

	global := ed25519.Sign(private, append(append([]byte{}, signature...), []byte(trustedComment)...))

	var b strings.Builder
	b.WriteString("untrusted comment: signature from a test key\n")
	b.WriteString(base64.StdEncoding.EncodeToString(sigBlob) + "\n")
	b.WriteString("trusted comment: " + trustedComment + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(global) + "\n")

	return []byte(b.String())
}

// The legacy algorithm signs the raw file rather than its hash. Older minisign
// and signify emit it, so it has to work - and the real fixture only covers
// the prehashed path.
func TestVerifyLegacyAlgorithm(t *testing.T) {
	asrt := assert.New(t)

	publicKey, private, err := newMinisignKeypair(t)
	require.NoError(t, err)

	content := []byte("a bundle's bytes")
	signature := signMinisign(t, publicKey, private, content, false, "file:bundle.tar.gz")

	sig, err := bundle.VerifyBundle(publicKey, signature, content)
	asrt.NoError(err)
	asrt.False(sig.Prehashed)

	// And it still detects a change.
	_, err = bundle.VerifyBundle(publicKey, signature, []byte("different bytes"))
	asrt.ErrorIs(err, bundle.ErrSignatureInvalid)
}

func TestParsePublicKey(t *testing.T) {
	asrt := assert.New(t)

	// The bare base64 line, and the whole two-line file: an operator will
	// paste whichever they have to hand.
	bare, err := bundle.ParsePublicKey(minisignUpstreamKey)
	asrt.NoError(err)

	full, err := bundle.ParsePublicKey(
		"untrusted comment: minisign public key\n" + minisignUpstreamKey + "\n")
	asrt.NoError(err)
	asrt.Equal(bare.KeyID, full.KeyID)
	asrt.Equal(bare.Key, full.Key)

	// The key ID is rendered the way the minisign CLI shows it, or an operator
	// cannot match a log line against their own key.
	asrt.NotEmpty(bare.KeyIDHex())
	asrt.Len(bare.KeyIDHex(), 16)

	for name, input := range map[string]string{
		"empty":           "",
		"comment only":    "untrusted comment: nothing here\n",
		"not base64":      "this is not base64 at all!!",
		"too short":       base64.StdEncoding.EncodeToString([]byte("Ed" + "short")),
		"wrong algorithm": base64.StdEncoding.EncodeToString(append([]byte("XX"), make([]byte, 40)...)),
		"two key lines":   minisignUpstreamKey + "\n" + minisignUpstreamKey,
	} {
		_, err := bundle.ParsePublicKey(input)
		asrt.ErrorIs(err, bundle.ErrBadPublicKey, name)
	}
}

func TestParseSignatureRejectsMalformed(t *testing.T) {
	asrt := assert.New(t)

	good, err := os.ReadFile(filepath.Join("testdata", "minisign-0.12.tar.gz.minisig"))
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(good)), "\n")
	require.Len(t, lines, 4)

	for name, input := range map[string]string{
		"empty":                "",
		"comment only":         lines[0] + "\n",
		"no trusted comment":   lines[0] + "\n" + lines[1] + "\n" + lines[3] + "\n",
		"no global signature":  lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n",
		"signature not base64": lines[0] + "\nnot base64!!\n" + lines[2] + "\n" + lines[3] + "\n",
		"extra line":           string(good) + base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n",
	} {
		_, err := bundle.ParseSignature([]byte(input))
		asrt.ErrorIs(err, bundle.ErrBadSignatureFile, name)
	}

	// An unknown algorithm is named rather than silently treated as one of the
	// two known ones.
	blob := append([]byte("XX"), make([]byte, 72)...)
	unknown := lines[0] + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n" +
		lines[2] + "\n" + lines[3] + "\n"

	_, err = bundle.ParseSignature([]byte(unknown))
	asrt.ErrorIs(err, bundle.ErrBadSignatureFile)
	asrt.Contains(err.Error(), "unknown algorithm")

	// An absurdly large file is refused before being parsed.
	_, err = bundle.ParseSignature([]byte(strings.Repeat("x", 1<<20)))
	asrt.ErrorIs(err, bundle.ErrBadSignatureFile)
}

// A signature whose own signature verifies but whose global signature does not
// must still be rejected. Checking only the first would leave the trusted
// comment unprotected.
func TestGlobalSignatureIsChecked(t *testing.T) {
	asrt := assert.New(t)

	publicKey, private, err := newMinisignKeypair(t)
	require.NoError(t, err)

	content := []byte("a bundle's bytes")
	signature := signMinisign(t, publicKey, private, content, true, "file:bundle.tar.gz")

	// Replace only the global signature line with a valid-length but wrong
	// value. The file signature is untouched and would still verify on its
	// own.
	lines := strings.Split(strings.TrimSpace(string(signature)), "\n")
	lines[3] = base64.StdEncoding.EncodeToString(make([]byte, 64))

	_, err = bundle.VerifyBundle(publicKey, []byte(strings.Join(lines, "\n")+"\n"), content)
	asrt.ErrorIs(err, bundle.ErrSignatureInvalid)
	asrt.Contains(err.Error(), "trusted comment")
}
