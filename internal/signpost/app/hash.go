package app

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns the hex SHA-256 of content.
//
// One helper rather than the three-line idiom repeated, because the digest is
// both an object's name and the ETag it is served with, and those two must
// never be computed differently.
func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)

	return hex.EncodeToString(digest[:])
}
