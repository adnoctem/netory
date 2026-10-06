package kv

import "errors"

// Sentinel errors returned by every Store implementation. They exist so that
// callers never have to match on a backend's own error values: gopskit's Get
// returns badger.ErrKeyNotFound verbatim, which would force pivot to import
// Badger in order to recognise a missing key in Valkey.
//
// Implementations wrap these with %w and add context, so callers use
// errors.Is rather than ==.
var (
	// ErrNotFound is returned by Get when the key does not exist.
	ErrNotFound = errors.New("kv: key not found")

	// ErrNotAnInteger is returned by Increment when the stored value is not a
	// decimal ASCII integer, or when the increment would overflow int64.
	ErrNotAnInteger = errors.New("kv: value is not an integer or out of range")

	// ErrInvalidNamespace is returned when a namespace fails ValidateNamespace.
	ErrInvalidNamespace = errors.New("kv: invalid namespace")

	// ErrInvalidKey is returned when a key fails ValidateKey.
	ErrInvalidKey = errors.New("kv: invalid key")

	// ErrClosed is returned by any operation on a closed Store.
	ErrClosed = errors.New("kv: store is closed")

	// ErrStopIteration is returned by a Scan callback to end the scan early.
	// Scan treats it as a clean stop and returns nil, so "find the first
	// match" needs no sentinel of the caller's own.
	ErrStopIteration = errors.New("kv: stop iteration")
)
