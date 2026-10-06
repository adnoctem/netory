package kv

import (
	"fmt"
	"strings"
)

const (
	// MaxNamespaceLen bounds a namespace name. Namespaces are compile-time
	// constants in all three services, so this is a typo guard rather than a
	// real constraint.
	MaxNamespaceLen = 64

	// MaxKeyLen bounds a namespace-relative key. The limit is central so that
	// an oversized key is ErrInvalidKey from every backend, instead of a
	// Badger-specific error from one and a silent success from the other.
	MaxKeyLen = 1024
)

// ValidateNamespace reports whether ns is usable as a namespace.
//
// The charset is restricted to ASCII letters, digits, '.', '_' and '-'. That
// excludes both '/' and ':', which is the point: the Badger implementation
// joins namespace and key with '/' and the Valkey one with ':', so forbidding
// both here means neither can produce an ambiguous physical key, and each
// backend keeps its idiomatic separator.
func ValidateNamespace(ns string) error {
	if ns == "" {
		return fmt.Errorf("%w: namespace is empty", ErrInvalidNamespace)
	}

	if len(ns) > MaxNamespaceLen {
		return fmt.Errorf("%w: namespace is %d bytes, limit is %d", ErrInvalidNamespace, len(ns), MaxNamespaceLen)
	}

	for i := 0; i < len(ns); i++ {
		c := ns[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf(
				"%w: namespace %q contains %q at offset %d, allowed are ASCII letters, digits, '.', '_' and '-'",
				ErrInvalidNamespace, ns, string(c), i,
			)
		}
	}

	return nil
}

// ValidateKey reports whether key is usable as a namespace-relative key.
//
// Unlike gopskit, which rejects any key containing '/', keys here may contain
// separators. They have to: Keys and Scan take a prefix, which only means
// anything if keys are hierarchical, and the services store things like
// "host/example.org" and "outbox/<id>". The namespace charset above is what
// keeps the physical key unambiguous, so the key itself needs no such rule.
//
// NUL is rejected. Both backends would store it, but it terminates strings in
// most tooling an operator would use to inspect the store, and pivot already
// rejects null bytes in request paths for the same class of reason.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: key is empty", ErrInvalidKey)
	}

	if len(key) > MaxKeyLen {
		return fmt.Errorf("%w: key is %d bytes, limit is %d", ErrInvalidKey, len(key), MaxKeyLen)
	}

	if i := strings.IndexByte(key, 0x00); i >= 0 {
		return fmt.Errorf("%w: key contains a NUL byte at offset %d", ErrInvalidKey, i)
	}

	return nil
}

// validatePrefix checks a Keys or Scan prefix. An empty prefix is legal - it
// matches the whole namespace - so this is ValidateKey without the emptiness
// rule.
func validatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}

	return ValidateKey(prefix)
}

// Validate checks a namespace and key pair. Implementations call it at the top
// of every operation, which is what makes the validation symmetric: gopskit
// applies its key guard in Get, Set and Has but forgets it in Delete.
func Validate(ns, key string) error {
	if err := ValidateNamespace(ns); err != nil {
		return err
	}

	return ValidateKey(key)
}

// ValidatePrefixed checks a namespace and a Keys or Scan prefix.
func ValidatePrefixed(ns, prefix string) error {
	if err := ValidateNamespace(ns); err != nil {
		return err
	}

	return validatePrefix(prefix)
}
