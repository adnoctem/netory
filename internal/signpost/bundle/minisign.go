package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// minisign signature verification (§6.2, resolving §9.4).
//
// signpost verifies; it never signs. The operator signs a bundle out of band
// with the standard `minisign` CLI, which is widely packaged, and signpost
// checks the detached signature at publish time. That split is the point: a
// service that holds signing keys is a service whose compromise forges
// releases, and signpost's whole posture is that the publish path has no
// remotely reachable attack surface.
//
// The format is small enough to verify in-repo over stdlib crypto/ed25519
// rather than take a library for. Only BLAKE2b comes from outside, because
// modern minisign prehashes and Go has no BLAKE2b in the standard library.
//
// Public key:
//
//	untrusted comment: <text>
//	base64( "Ed" || key_id[8] || public_key[32] )
//
// Signature:
//
//	untrusted comment: <text>
//	base64( alg[2] || key_id[8] || signature[64] )
//	trusted comment: <text>
//	base64( global_signature[64] )
//
// alg is "Ed" for a signature over the raw file, or "ED" for one over
// BLAKE2b-512 of it. The global signature covers signature || trusted_comment,
// which is what binds the trusted comment to the signature.

// Sizes of the fields in a minisign blob.
const (
	minisignAlgLen     = 2
	minisignKeyIDLen   = 8
	minisignPubKeyLen  = ed25519.PublicKeySize
	minisignSigLen     = ed25519.SignatureSize
	minisignPubKeyBlob = minisignAlgLen + minisignKeyIDLen + minisignPubKeyLen
	minisignSigBlob    = minisignAlgLen + minisignKeyIDLen + minisignSigLen
)

// The signature algorithms minisign emits.
var (
	algLegacy    = [2]byte{'E', 'd'}
	algPrehashed = [2]byte{'E', 'D'}
)

// trustedCommentPrefix introduces the trusted comment line.
//
// minisign writes "trusted comment: " with a space; the spec names the field
// "trusted_comment". Both spellings are accepted on read, because a signature
// that verifies cryptographically should not be rejected over a label.
var trustedCommentPrefixes = []string{"trusted comment:", "trusted_comment:"}

// maxSignatureBytes bounds a .minisig file. It is four short lines; anything
// larger is not one.
const maxSignatureBytes = 8 << 10

// Sentinel errors.
var (
	// ErrBadPublicKey is returned for a malformed public key.
	ErrBadPublicKey = errors.New("bundle: malformed minisign public key")

	// ErrBadSignatureFile is returned for a malformed signature file.
	ErrBadSignatureFile = errors.New("bundle: malformed minisign signature")

	// ErrKeyMismatch is returned when the signature was made by a different
	// key than the one supplied.
	ErrKeyMismatch = errors.New("bundle: the signature was made by a different key")

	// ErrSignatureInvalid is returned when the signature does not verify.
	ErrSignatureInvalid = errors.New("bundle: the signature does not verify")
)

// PublicKey is a parsed minisign public key.
type PublicKey struct {
	// KeyID identifies the key, and is echoed in signatures it makes.
	KeyID [minisignKeyIDLen]byte

	// Key is the Ed25519 public key.
	Key ed25519.PublicKey
}

// KeyIDHex renders the key ID for logs and the audit record.
//
// minisign prints the key ID in reverse byte order, so this matches what the
// CLI shows an operator - a log line they cannot match against their own key
// is a log line that does not help.
func (p PublicKey) KeyIDHex() string {
	reversed := make([]byte, len(p.KeyID))
	for i, b := range p.KeyID {
		reversed[len(p.KeyID)-1-i] = b
	}

	return fmt.Sprintf("%X", reversed)
}

// ParsePublicKey reads a minisign public key.
//
// It accepts both the whole two-line public-key file and the bare base64 line,
// because an operator will paste whichever they have to hand and failing on
// the difference would be gratuitous.
func ParsePublicKey(input string) (PublicKey, error) {
	encoded := ""

	for _, line := range strings.Split(normaliseNewlines(input), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}

		if encoded != "" {
			return PublicKey{}, fmt.Errorf("%w: more than one key line", ErrBadPublicKey)
		}

		encoded = line
	}

	if encoded == "" {
		return PublicKey{}, fmt.Errorf("%w: no key found", ErrBadPublicKey)
	}

	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: not base64: %w", ErrBadPublicKey, err)
	}

	if len(blob) != minisignPubKeyBlob {
		return PublicKey{}, fmt.Errorf(
			"%w: %d bytes, expected %d", ErrBadPublicKey, len(blob), minisignPubKeyBlob)
	}

	if alg := [2]byte(blob[:minisignAlgLen]); alg != algLegacy {
		// A public key always carries "Ed"; the prehashed marker appears on
		// signatures, not on keys.
		return PublicKey{}, fmt.Errorf(
			"%w: unexpected algorithm %q", ErrBadPublicKey, string(blob[:minisignAlgLen]))
	}

	var key PublicKey
	copy(key.KeyID[:], blob[minisignAlgLen:minisignAlgLen+minisignKeyIDLen])
	key.Key = ed25519.PublicKey(blob[minisignAlgLen+minisignKeyIDLen:])

	return key, nil
}

// Signature is a parsed minisign signature.
type Signature struct {
	// Prehashed reports whether the signature covers BLAKE2b-512 of the file
	// rather than the file itself.
	Prehashed bool

	// KeyID identifies the key that made it.
	KeyID [minisignKeyIDLen]byte

	// Sig is the Ed25519 signature over the message.
	Sig []byte

	// TrustedComment is the comment bound to the signature by the global
	// signature. minisign conventionally puts the filename and a timestamp
	// here, and unlike the untrusted comment it cannot be altered without the
	// secret key.
	TrustedComment string

	// GlobalSig covers Sig || TrustedComment.
	GlobalSig []byte
}

// ParseSignature reads a .minisig file.
func ParseSignature(input []byte) (Signature, error) {
	if len(input) == 0 {
		return Signature{}, fmt.Errorf("%w: the file is empty", ErrBadSignatureFile)
	}

	if len(input) > maxSignatureBytes {
		return Signature{}, fmt.Errorf(
			"%w: %d bytes, which is far larger than a signature", ErrBadSignatureFile, len(input))
	}

	lines := strings.Split(normaliseNewlines(string(input)), "\n")

	var (
		sigBlob        string
		globalBlob     string
		trustedComment string
		haveTrusted    bool
	)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "untrusted comment:") {
			continue
		}

		if comment, ok := trustedComment2(trimmed); ok {
			trustedComment, haveTrusted = comment, true

			continue
		}

		switch {
		case sigBlob == "":
			sigBlob = trimmed
		case globalBlob == "":
			globalBlob = trimmed
		default:
			return Signature{}, fmt.Errorf("%w: unexpected extra line", ErrBadSignatureFile)
		}
	}

	if sigBlob == "" || globalBlob == "" || !haveTrusted {
		return Signature{}, fmt.Errorf(
			"%w: expected an untrusted comment, a signature, a trusted comment and a global signature",
			ErrBadSignatureFile)
	}

	blob, err := base64.StdEncoding.DecodeString(sigBlob)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: the signature line is not base64: %w", ErrBadSignatureFile, err)
	}

	if len(blob) != minisignSigBlob {
		return Signature{}, fmt.Errorf(
			"%w: the signature is %d bytes, expected %d", ErrBadSignatureFile, len(blob), minisignSigBlob)
	}

	global, err := base64.StdEncoding.DecodeString(globalBlob)
	if err != nil {
		return Signature{}, fmt.Errorf(
			"%w: the global signature line is not base64: %w", ErrBadSignatureFile, err)
	}

	if len(global) != minisignSigLen {
		return Signature{}, fmt.Errorf(
			"%w: the global signature is %d bytes, expected %d",
			ErrBadSignatureFile, len(global), minisignSigLen)
	}

	alg := [2]byte(blob[:minisignAlgLen])

	var prehashed bool
	switch alg {
	case algPrehashed:
		prehashed = true
	case algLegacy:
		prehashed = false
	default:
		return Signature{}, fmt.Errorf(
			"%w: unknown algorithm %q", ErrBadSignatureFile, string(blob[:minisignAlgLen]))
	}

	signature := Signature{
		Prehashed:      prehashed,
		Sig:            blob[minisignAlgLen+minisignKeyIDLen:],
		TrustedComment: trustedComment,
		GlobalSig:      global,
	}
	copy(signature.KeyID[:], blob[minisignAlgLen:minisignAlgLen+minisignKeyIDLen])

	return signature, nil
}

// trustedComment2 extracts the trusted comment from a line, if it is one.
func trustedComment2(line string) (string, bool) {
	for _, prefix := range trustedCommentPrefixes {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
		}
	}

	return "", false
}

// Verify checks a signature over content against a public key.
//
// Both signatures are checked, not just the first. The global signature is
// what binds the trusted comment to the release, and skipping it would let
// anyone rewrite the comment that signpost records in its audit log - which
// is precisely the field an auditor would rely on.
func Verify(key PublicKey, sig Signature, content []byte) error {
	// Constant-time, though the key ID is not secret: it costs nothing and
	// keeps the comparison out of the set of things to think about later.
	if subtle.ConstantTimeCompare(key.KeyID[:], sig.KeyID[:]) != 1 {
		return fmt.Errorf("%w: signature key ID does not match %s", ErrKeyMismatch, key.KeyIDHex())
	}

	message := content
	if sig.Prehashed {
		digest := blake2b.Sum512(content)
		message = digest[:]
	}

	if !ed25519.Verify(key.Key, message, sig.Sig) {
		return ErrSignatureInvalid
	}

	// The global signature covers signature || trusted_comment.
	var global bytes.Buffer
	global.Write(sig.Sig)
	global.WriteString(sig.TrustedComment)

	if !ed25519.Verify(key.Key, global.Bytes(), sig.GlobalSig) {
		return fmt.Errorf("%w: the trusted comment is not covered by the signature", ErrSignatureInvalid)
	}

	return nil
}

// VerifyBundle is the whole check in one call: parse the key, parse the
// signature, verify both over the archive bytes.
func VerifyBundle(publicKey string, signature, archive []byte) (Signature, error) {
	key, err := ParsePublicKey(publicKey)
	if err != nil {
		return Signature{}, err
	}

	sig, err := ParseSignature(signature)
	if err != nil {
		return Signature{}, err
	}

	if err := Verify(key, sig, archive); err != nil {
		return Signature{}, err
	}

	return sig, nil
}
