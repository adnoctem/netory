package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/adnoctem/netory/internal/signpost/app"
)

// These tests exercise the publish path's signature policy with a key they
// generate themselves.
//
// What they do not establish is that signpost reads minisign's format
// correctly - a signer and a verifier written from the same misunderstanding
// agree with each other perfectly. That is pinned separately in
// bundle/minisign_test.go against a genuine signature from jedisct1's own
// minisign releases. These tests are about the plumbing above it: that a
// verified signature reaches the release record, that a required one is
// enforced, and that the recorded key ID and trusted comment are the ones
// that were actually checked.

// minisignKeypair generates a keypair with the public key in minisign's
// one-line encoding.
func minisignKeypair(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID := make([]byte, 8)
	_, err = rand.Read(keyID)
	require.NoError(t, err)

	blob := append([]byte{'E', 'd'}, keyID...)
	blob = append(blob, pub...)

	return base64.StdEncoding.EncodeToString(blob), priv
}

// signBundle produces a prehashed minisign signature over content, which is
// what `minisign -Sm` emits.
func signBundle(t *testing.T, publicKey string, private ed25519.PrivateKey, content []byte) []byte {
	t.Helper()

	blob, err := base64.StdEncoding.DecodeString(publicKey)
	require.NoError(t, err)

	digest := blake2b.Sum512(content)
	signature := ed25519.Sign(private, digest[:])

	sigBlob := append([]byte{'E', 'D'}, blob[2:10]...)
	sigBlob = append(sigBlob, signature...)

	comment := "timestamp:1760000000\tfile:bundle.tar.gz"
	global := ed25519.Sign(private, append(append([]byte{}, signature...), []byte(comment)...))

	var out strings.Builder

	out.WriteString("untrusted comment: signature from a test key\n")
	out.WriteString(base64.StdEncoding.EncodeToString(sigBlob) + "\n")
	out.WriteString("trusted comment: " + comment + "\n")
	out.WriteString(base64.StdEncoding.EncodeToString(global) + "\n")

	return []byte(out.String())
}

func TestPublishWithAVerifiedSignature(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	publicKey, private := minisignKeypair(t)
	archive := simpleBundle(t, "1.0.0", "  echo signed")

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	// Both set, so this also proves the required-signature gate opens for a
	// signature that verifies rather than merely for one that is present.
	settings.RequireSignature = true
	settings.SigningKey = publicKey
	require.NoError(t, state.ApplySettings(ctx, settings))

	result, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive:   archive,
		Signature: signBundle(t, publicKey, private, archive),
		By:        publisher,
	})
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.True(result.Release.Signature.Verified)
	asrt.True(result.Release.Signature.Prehashed)
	asrt.NotEmpty(result.Release.Signature.KeyID)
	asrt.Equal("timestamp:1760000000\tfile:bundle.tar.gz", result.Release.Signature.TrustedComment,
		"§8.1 wants the signature status in the audit trail, and the trusted comment is the part of it the signer chose")
	asrt.Contains(result.Release.Signature.Status(), "verified")
}

// A signature over different bytes is refused, which is the whole point: the
// signature says "these bytes", not "this release name".
func TestPublishRefusesASignatureOverOtherBytes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	publicKey, private := minisignKeypair(t)

	signed := simpleBundle(t, "1.0.0", "  echo signed")
	other := simpleBundle(t, "1.0.0", "  echo substituted")

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive:   other,
		Signature: signBundle(t, publicKey, private, signed),
		PublicKey: publicKey,
		By:        publisher,
	})
	require.Error(t, err)

	releases, listErr := state.Releases.List(ctx)
	require.NoError(t, listErr)
	assert.Empty(t, releases)
}

// A signature from a key the instance does not trust is refused, even though
// it is a perfectly valid signature over exactly these bytes.
func TestPublishRefusesAnUntrustedKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	trusted, _ := minisignKeypair(t)
	attacker, attackerPrivate := minisignKeypair(t)

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	settings.SigningKey = trusted
	require.NoError(t, state.ApplySettings(ctx, settings))

	archive := simpleBundle(t, "1.0.0", "  echo signed")

	_, err = state.PublishBundle(ctx, app.PublishRequest{
		Archive:   archive,
		Signature: signBundle(t, attacker, attackerPrivate, archive),
		By:        publisher,
	})
	require.Error(t, err)
}

// --public-key overrides the configured key for one publish, which is how a
// key rotation is done without a window in which nothing verifies.
func TestPublishWithAnOverriddenKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	configured, _ := minisignKeypair(t)
	rotated, rotatedPrivate := minisignKeypair(t)

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	settings.SigningKey = configured
	settings.RequireSignature = true
	require.NoError(t, state.ApplySettings(ctx, settings))

	archive := simpleBundle(t, "1.0.0", "  echo rotated")

	result, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive:   archive,
		Signature: signBundle(t, rotated, rotatedPrivate, archive),
		PublicKey: rotated,
		By:        publisher,
	})
	require.NoError(t, err)

	assert.True(t, result.Release.Signature.Verified)
}
