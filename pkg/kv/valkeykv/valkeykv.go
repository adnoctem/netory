// Package valkeykv implements kv.Store on top of Valkey.
//
// It is the store for pivot, which is the one netory service designed to run
// as several replicas behind a load balancer. That is the whole reason this
// implementation exists: Badger holds an exclusive lock on its directory, so
// it can only ever back a single-process service, while every piece of pivot's
// state - hashed client secrets, issued tokens, rate-limit counters, cached
// responses, the notification outbox - has to be visible to every replica at
// once.
//
// # Valkey has no encryption at rest
//
// Badger encrypts its files with a key derived from the service secret, so
// badgerkv callers can store a credential and rely on the store to protect it.
// Valkey offers no equivalent, and this package deliberately does not pretend
// otherwise: it stores exactly the bytes it is given. pivot encrypts the
// values that need it before they reach this package. A caller that hands a plaintext credential to this store has
// written a plaintext credential to Valkey.
//
// # Client-side caching is available and unused
//
// valkey-go supports server-assisted client-side caching, and this package
// never uses it. Every read here goes to the server. The values it holds are
// rate-limit counters, token records and outbox claims - state whose whole
// purpose is to be shared and current across replicas - and a cached read of
// any of them is a rate limit that does not limit or a revoked token that
// still works. pivot's response cache is a different thing built on
// top of this store, not a property of the store itself.
package valkeykv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/adnoctem/netory/pkg/kv"
)

// separator joins a namespace and a key into the physical Valkey key.
//
// A colon, which is Valkey's convention and which kv.ValidateNamespace
// excludes from a namespace - as it excludes Badger's '/' - so a physical key
// splits back apart unambiguously no matter which backend produced it.
const separator = ':'

// DefaultScanCount is how many keys one SCAN cursor step asks for.
//
// SCAN's COUNT is a hint about work per call, not a page size. Larger values
// mean fewer round trips and a longer single-command latency; Valkey is
// single-threaded for command execution, so a very large COUNT is a way to
// stall every other client. A few hundred keeps each step short while keeping
// a namespace walk to a sensible number of round trips.
const DefaultScanCount int64 = 256

// Options configures a Store.
type Options struct {
	// Address is one or more Valkey nodes as host:port. Required.
	//
	// Several addresses means a cluster or a replica set, which valkey-go
	// discovers for itself from the first one that answers.
	Address []string

	// Username and Password authenticate the connection. Valkey 6 ACLs use
	// both; a legacy requirepass setup leaves Username empty.
	Username string
	Password string

	// DB selects a logical database. Ignored by a Valkey cluster, which has
	// only database 0 - so nothing in netory should rely on it.
	DB int

	// TLSConfig enables TLS to the server. Nil means a plaintext connection,
	// which is only acceptable on a trusted network: everything this store
	// holds is either a credential, a hash of one, or state an attacker would
	// like to forge.
	TLSConfig *tls.Config

	// ClientName labels the connection in Valkey's CLIENT LIST, so an
	// operator looking at a busy server can tell which service a connection
	// belongs to.
	ClientName string

	// ScanCount overrides DefaultScanCount.
	ScanCount int64

	// ClientSideCache enables valkey-go's server-assisted caching for callers
	// that opt in per command. The Store itself never opts in; see the package
	// documentation.
	//
	// Left off by default for a second, practical reason: valkey-go refuses to
	// connect to a server that cannot support tracking unless caching is
	// disabled, so leaving it on would make this store fail against an older
	// Valkey or a proxy that does not implement CLIENT TRACKING - for a
	// feature nothing here uses.
	ClientSideCache bool

	// Client is an already-built valkey-go client to use instead of dialling
	// one. The Store does not close a client it did not create, so the caller
	// keeps ownership of its lifetime.
	Client valkey.Client
}

// Store is a kv.Store backed by Valkey.
type Store struct {
	client valkey.Client

	// ownsClient records whether New dialled the client, which decides
	// whether Close may close it.
	ownsClient bool

	// scanCount is the resolved SCAN hint.
	scanCount int64

	// closed is checked at the top of every operation so a use-after-Close is
	// kv.ErrClosed rather than valkey-go's own closed-client error.
	closed atomic.Bool

	closeOnce sync.Once
}

// enforce implementation of the interface
var _ kv.Store = (*Store)(nil)

// New connects to Valkey and returns it as a kv.Store.
func New(opts Options) (*Store, error) {
	store := &Store{
		scanCount: opts.ScanCount,
	}

	if store.scanCount <= 0 {
		store.scanCount = DefaultScanCount
	}

	if opts.Client != nil {
		store.client = opts.Client

		return store, nil
	}

	if len(opts.Address) == 0 {
		return nil, errors.New("valkeykv: at least one address is required")
	}

	for i, addr := range opts.Address {
		if strings.TrimSpace(addr) == "" {
			return nil, fmt.Errorf("valkeykv: address %d is empty", i)
		}
	}

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  opts.Address,
		Username:     opts.Username,
		Password:     opts.Password,
		SelectDB:     opts.DB,
		TLSConfig:    opts.TLSConfig,
		ClientName:   opts.ClientName,
		DisableCache: !opts.ClientSideCache,
	})
	if err != nil {
		return nil, fmt.Errorf("valkeykv: connect to %s: %w", strings.Join(opts.Address, ", "), err)
	}

	store.client = client
	store.ownsClient = true

	return store, nil
}

// Get implements kv.Store.
func (s *Store) Get(ctx context.Context, ns, key string) ([]byte, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return nil, err
	}

	value, err := s.client.Do(ctx, s.client.B().Get().Key(physical(ns, key)).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, fmt.Errorf("%w: %s/%s", kv.ErrNotFound, ns, key)
		}

		return nil, s.translate(err, "get", ns, key)
	}

	return value, nil
}

// Set implements kv.Store.
func (s *Store) Set(ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption) error {
	if err := s.precheck(ctx, ns, key); err != nil {
		return err
	}

	o := kv.ResolveSetOptions(opts...)
	physicalKey := physical(ns, key)

	// A write with no TTL clears any expiry the key already had, which is
	// what Badger does: its entry carries no ExpiresAt, so the new value is
	// permanent regardless of what it replaced. Valkey's plain SET behaves the
	// same way, so neither backend needs KEEPTTL to agree with the other.
	// Built once in each branch rather than built and then rebuilt:
	// valkey-go's builders are single-use and panic on a second Build.
	cmd := s.client.B().Set().Key(physicalKey).Value(valkey.BinaryString(value)).Build()
	if expiry, ok := expiresAt(o); ok {
		cmd = s.client.B().Set().Key(physicalKey).Value(valkey.BinaryString(value)).
			Pxat(expiry).Build()
	}

	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		return s.translate(err, "set", ns, key)
	}

	return nil
}

// Has implements kv.Store.
func (s *Store) Has(ctx context.Context, ns, key string) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	// EXISTS rather than a GET whose result is thrown away: it reports key
	// existence without moving the value over the wire, and the contract is
	// that a key holding an empty value exists.
	count, err := s.client.Do(ctx, s.client.B().Exists().Key(physical(ns, key)).Build()).ToInt64()
	if err != nil {
		return false, s.translate(err, "has", ns, key)
	}

	return count > 0, nil
}

// Delete implements kv.Store.
func (s *Store) Delete(ctx context.Context, ns, key string) error {
	if err := s.precheck(ctx, ns, key); err != nil {
		return err
	}

	// DEL on an absent key answers 0 rather than erroring, so idempotent
	// deletion needs nothing added here.
	if err := s.client.Do(ctx, s.client.B().Del().Key(physical(ns, key)).Build()).Error(); err != nil {
		return s.translate(err, "delete", ns, key)
	}

	return nil
}

// Keys implements kv.Store.
func (s *Store) Keys(ctx context.Context, ns, prefix string) ([]string, error) {
	if err := s.precheckPrefix(ctx, ns, prefix); err != nil {
		return nil, err
	}

	var keys []string

	err := s.scanKeys(ctx, ns, prefix, func(relative string) error {
		keys = append(keys, relative)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// Scan implements kv.Store.
func (s *Store) Scan(ctx context.Context, ns, prefix string, fn func(kv.Entry) error) error {
	if err := s.precheckPrefix(ctx, ns, prefix); err != nil {
		return err
	}

	if fn == nil {
		return errors.New("valkeykv: scan requires a callback")
	}

	return s.scanKeys(ctx, ns, prefix, func(relative string) error {
		value, err := s.client.Do(ctx, s.client.B().Get().Key(physical(ns, relative)).Build()).AsBytes()
		if err != nil {
			if valkey.IsValkeyNil(err) {
				// The key expired or was deleted between the SCAN that found
				// it and this read. Skipped rather than reported: a scan is
				// not a snapshot on either backend, and an entry that no
				// longer exists is not an entry.
				return nil
			}

			return s.translate(err, "scan", ns, relative)
		}

		return fn(kv.Entry{Key: relative, Value: value})
	})
}

// SetIfAbsent implements kv.Store.
func (s *Store) SetIfAbsent(
	ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption,
) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	o := kv.ResolveSetOptions(opts...)
	physicalKey := physical(ns, key)

	// SET NX is a single atomic server-side operation, which is what makes
	// this usable as the create-exclusively primitive behind pivot's token
	// issuance: two replicas racing to issue the same token cannot both be
	// told they wrote it.
	//
	// Built once in each branch, as in Set: a valkey-go builder is single-use.
	cmd := s.client.B().Set().Key(physicalKey).Value(valkey.BinaryString(value)).Nx().Build()
	if expiry, ok := expiresAt(o); ok {
		cmd = s.client.B().Set().Key(physicalKey).Value(valkey.BinaryString(value)).Nx().
			Pxat(expiry).Build()
	}

	err := s.client.Do(ctx, cmd).Error()
	switch {
	case err == nil:
		return true, nil
	case valkey.IsValkeyNil(err):
		// SET NX answers a nil reply when the key already existed, which is
		// not a failure.
		return false, nil
	default:
		return false, s.translate(err, "set-if-absent", ns, key)
	}
}

// CompareAndSwap implements kv.Store.
//
// Valkey has no native compare-and-swap, so this is a Lua script: the compare
// and the write happen inside one server-side execution with nothing able to
// interleave. WATCH and MULTI would also work and would be worse here - a
// pooled connection shared by many goroutines makes per-connection WATCH state
// something to reason about, and a script has none.
func (s *Store) CompareAndSwap(
	ctx context.Context, ns, key string, expected, value []byte, opts ...kv.SetOption,
) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	o := kv.ResolveSetOptions(opts...)

	expiry, hasTTL := expiresAtMillis(o)
	args := []string{
		valkey.BinaryString(expected),
		valkey.BinaryString(value),
		boolArg(hasTTL),
		strconv.FormatInt(expiry, 10),
	}

	wrote, err := casScript.Exec(ctx, s.client, []string{physical(ns, key)}, args).ToInt64()
	if err != nil {
		return false, s.translate(err, "compare-and-swap", ns, key)
	}

	return wrote == 1, nil
}

// Increment implements kv.Store.
//
// INCRBY is native and atomic, which is the reason kv.Store specifies a
// counter as decimal ASCII rather than as an encoding of its own: pivot's rate
// limiter is the hottest write path in the three services, and it costs one
// round trip here instead of a read-modify-write.
//
// The expiry handling is in the same script as the increment rather than a
// second command afterwards. A window counter whose TTL is set by a separate
// call has a moment in which it exists without one, and a crash in that moment
// leaves a counter that never resets - a client rate-limited forever.
func (s *Store) Increment(
	ctx context.Context, ns, key string, delta int64, opts ...kv.SetOption,
) (int64, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return 0, err
	}

	o := kv.ResolveSetOptions(opts...)

	expiry, hasTTL := expiresAtMillis(o)
	args := []string{
		strconv.FormatInt(delta, 10),
		boolArg(hasTTL),
		strconv.FormatInt(expiry, 10),
	}

	next, err := incrementScript.Exec(ctx, s.client, []string{physical(ns, key)}, args).ToInt64()
	if err != nil {
		return 0, s.translate(err, "increment", ns, key)
	}

	return next, nil
}

// Close implements kv.Store.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)

		// A client the caller supplied is left alone: it may be shared with
		// something else, and closing a connection pool out from under its
		// owner is not this store's decision to make.
		if s.ownsClient && s.client != nil {
			s.client.Close()
		}
	})

	return nil
}

// Client returns the underlying valkey-go client.
//
// On the concrete type rather than the interface, for the same reason
// badgerkv.Store keeps Path and Options off it: pivot needs Valkey commands
// this contract does not express - PUBLISH for rule reloads, SCAN patterns
// across namespaces - and kv.Store must stay implementable by both backends.
func (s *Store) Client() valkey.Client { return s.client }

// Ping reports whether the server is reachable, for a health endpoint and for
// `pivot server start` to fail loudly at startup rather than on the first
// request.
func (s *Store) Ping(ctx context.Context) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := s.client.Do(ctx, s.client.B().Ping().Build()).Error(); err != nil {
		return fmt.Errorf("valkeykv: ping: %w", err)
	}

	return nil
}

// expiresAt resolves a TTL to the absolute expiry Valkey's PXAT takes.
//
// It goes through kv.ExpiresAt rather than computing an expiry of its own,
// even though PXAT could express the exact duration. The contract says a TTL
// is a lower bound rounded up to kv.TTLGranularity, and the point of a shared
// helper is that both backends round the same way - a key expiring at
// slightly different moments depending on the backend would be a difference
// the conformance suite could not see but a service could.
func expiresAt(o kv.SetOptions) (time.Time, bool) {
	expiry := kv.ExpiresAt(time.Now(), o.TTL)
	if expiry.IsZero() {
		return time.Time{}, false
	}

	return expiry, true
}

// expiresAtMillis is expiresAt rendered for a Lua argument, which arrives as
// a string whatever its type.
func expiresAtMillis(o kv.SetOptions) (int64, bool) {
	expiry, ok := expiresAt(o)
	if !ok {
		return 0, false
	}

	return expiry.UnixMilli(), true
}

// boolArg renders a flag for a Lua script, which has no boolean argument type:
// every ARGV entry arrives as a string.
func boolArg(value bool) string {
	if value {
		return "1"
	}

	return "0"
}

// PhysicalKey renders the Valkey key a namespace and key resolve to.
//
// Exported for the one legitimate reason to reach past kv.Store: a caller
// running a Lua script through Client needs to name the same keys the store
// would. pivot's token-bucket limiter is that caller - a bucket refill is a
// read-modify-write the interface cannot express atomically, so it is a script,
// and a script that built its own key format would drift from the store's the
// moment either changed.
//
// The namespace and key are validated, so a caller cannot construct a key the
// store itself would have refused.
func PhysicalKey(ns, key string) (string, error) {
	if err := kv.Validate(ns, key); err != nil {
		return "", err
	}

	return physical(ns, key), nil
}
