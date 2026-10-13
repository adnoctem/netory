package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/cache"
	"github.com/adnoctem/netory/internal/pivot/rules"
)

// hopHeaders are the connection-level headers that must not be forwarded in
// either direction (RFC 9110 §7.6.1).
//
// A proxy that forwarded Connection or Transfer-Encoding would be describing
// its own hop to the next one, and a forwarded Keep-Alive or Upgrade is how a
// request smuggling or protocol-confusion bug starts.
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// clientHeaders are the request headers pivot drops before forwarding.
//
// Authorization above all: the client authenticated to pivot, and the forward
// leg carries pivot's own credentials instead. Forwarding the customer's would
// let it try to authenticate to the backend directly, which is the one thing
// "credentials never leave pivot" is about - in the other direction.
var clientHeaders = []string{
	"Authorization",
	"Cookie",
}

// serve runs the pipeline's later stages: cache lookup, coalesce, concurrency
// limit, forward, then store and respond.
func (s *Server) serve(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	client app.Client,
	settings app.Settings,
	path string,
	body []byte,
	result *outcome,
) {
	if settings.BackendURL == "" {
		s.log.Error("no backend URL is configured, so nothing can be forwarded")

		result.status = http.StatusServiceUnavailable
		s.fail(w, result.status, "unavailable", "pivot has no backend configured")

		return
	}

	set := s.state.Reloader.Table().For(client.ID)
	key, cacheConfig, cacheable := s.cacheKeyFor(client, set, r.Method, path, r.URL.RawQuery, body)

	// Stage 6: cache lookup.
	if cacheable {
		entry, found, err := s.state.Cache.Get(ctx, key, cacheConfig.Encrypt)
		if err != nil {
			// A cache read failure is not a request failure: the backend can
			// still answer. Logged so a Valkey problem is visible.
			s.log.Warn("could not read the cache", "client", client.ID, "error", err)
		}

		if found {
			result.cache = cacheHit
			result.status = entry.Status

			s.writeEntry(w, entry, cacheHit)

			return
		}

		result.cache = cacheMiss
	}

	// An uncacheable route is streamed straight through: nothing downstream
	// needs the whole body, so there is no reason to buffer it and no reason
	// to bound it. That is what makes a large export work - a 200 MB report
	// on an uncached route is a copy, not a 32 MiB buffer and a 502.
	if !cacheable {
		s.stream(ctx, w, r, client, settings, path, body, result)

		return
	}

	// Stages 7 to 9. The whole backend call - slot, forward, read - is the
	// unit that gets coalesced, because what the followers want is the
	// response, and anything less than the whole call would have them waiting
	// for a slot of their own.
	call := func() (any, error) {
		return s.callBackend(ctx, r, client, settings, path, body)
	}

	var (
		response *backendResponse
		err      error
	)

	if cacheable && settings.Coalesce {
		shared, callErr := s.coalescer.Do(ctx, key.String(), call)
		if callErr == nil {
			response, _ = shared.Value.(*backendResponse)
			result.shared = shared.Shared
		}

		err = callErr
	} else {
		var value any

		value, err = call()
		if err == nil {
			response, _ = value.(*backendResponse)
		}
	}

	if err != nil {
		s.backendFailed(ctx, w, client, settings, err, result)

		return
	}

	if response == nil {
		result.status = http.StatusBadGateway
		s.fail(w, result.status, "bad_gateway", "the backend did not answer")

		return
	}

	result.upstream = true
	result.status = response.status

	// Stage 10: store, then respond.
	if cacheable && !result.shared {
		s.maybeCache(ctx, key, cacheConfig, response, client)
	}

	s.writeResponse(w, response, result.cache)
}

// backendResponse is a buffered backend reply.
//
// Buffered rather than streamed, because caching and coalescing both need the
// whole body - a stream can be sent to one reader. That is also why only a
// cacheable route takes this path: an uncacheable one is streamed straight
// through by stream, which has no size limit at all.
type backendResponse struct {
	status int
	header http.Header
	body   []byte
}

// callBackend acquires a slot and performs the forward leg.
func (s *Server) callBackend(
	ctx context.Context,
	r *http.Request,
	client app.Client,
	settings app.Settings,
	path string,
	body []byte,
) (*backendResponse, error) {
	// The concurrency limit: the mechanism that actually protects
	// production.
	release, err := s.concurrency.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	// Stage 9: forward.
	resp, err := s.sendBackend(ctx, r, client, settings, path, body)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// One byte beyond the limit is how an over-large response is detected
	// without trusting Content-Length, which is a claim.
	buffered, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the backend response: %w", err)
	}

	if len(buffered) > MaxResponseBodyBytes {
		return nil, fmt.Errorf("%w: the backend response is larger than %d bytes",
			errResponseTooLarge, MaxResponseBodyBytes)
	}

	return &backendResponse{
		status: resp.StatusCode,
		header: resp.Header.Clone(),
		body:   buffered,
	}, nil
}

// sendBackend builds and performs the forward leg, returning the live
// response.
//
// Shared by the buffered and the streaming paths, which is the part that must
// not exist twice: this is where the client's credentials are dropped and
// pivot's are added, and two copies of that would be two chances to forward
// the wrong one.
func (s *Server) sendBackend(
	ctx context.Context,
	r *http.Request,
	client app.Client,
	settings app.Settings,
	path string,
	body []byte,
) (*http.Response, error) {
	backend, err := s.state.Backend(client)
	if err != nil {
		return nil, fmt.Errorf("build the backend authenticator: %w", err)
	}

	target := settings.BackendURL + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	outbound, err := http.NewRequestWithContext(ctx, r.Method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("build the forward request: %w", err)
	}

	copyRequestHeaders(outbound, r)

	if len(body) > 0 {
		outbound.ContentLength = int64(len(body))
	}

	// pivot's own credentials go on last, after the client's have been
	// dropped, so there is never a moment where both are present.
	if err := backend.Authorize(ctx, outbound); err != nil {
		return nil, err
	}

	resp, err := s.backend.Do(outbound)
	if err != nil {
		return nil, fmt.Errorf("forward to the backend: %w", err)
	}

	return resp, nil
}

// errResponseTooLarge is returned when a cacheable route's response exceeds
// the buffer.
//
// Only reachable on a cacheable route: an uncacheable one streams, so there is
// nothing to exceed. A response this large on a route marked cacheable is a
// configuration mistake worth reporting rather than silently serving uncached,
// since the operator asked for it to be cached and it never will be.
var errResponseTooLarge = errors.New("server: the backend response is too large to cache")

// stream forwards a request and copies the reply straight to the client.
//
// Used for every route that is not cacheable, which is most of them. Nothing
// here needs the whole body, so it is never in memory at once: the response
// can be any size the customer is willing to wait for.
//
// Not coalesced, which follows from the same fact. Two identical concurrent
// requests for an uncached route each get their own backend call, because
// there is no shared buffer for a follower to read.
func (s *Server) stream(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	client app.Client,
	settings app.Settings,
	path string,
	body []byte,
	result *outcome,
) {
	release, err := s.concurrency.Acquire(ctx)
	if err != nil {
		s.backendFailed(ctx, w, client, settings, err, result)

		return
	}
	defer release()

	resp, err := s.sendBackend(ctx, r, client, settings, path, body)
	if err != nil {
		s.backendFailed(ctx, w, client, settings, err, result)

		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	result.upstream = true
	result.status = resp.StatusCode

	header := w.Header()

	for name, values := range resp.Header {
		for _, value := range values {
			header.Add(name, value)
		}
	}

	for _, name := range hopHeaders {
		header.Del(name)
	}

	header.Set(HeaderCacheStatus, cacheBypass)

	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		// The status and headers are already sent, so there is nothing to
		// report to the client. Logged, because a truncated response is a
		// real failure the customer will see as corrupt data.
		s.log.Warn("the response was cut short while streaming",
			"client", client.ID, "path", path, "error", err)
	}
}

// copyRequestHeaders copies the client's headers onto the forward request,
// dropping the ones that must not travel.
func copyRequestHeaders(outbound *http.Request, inbound *http.Request) {
	for name, values := range inbound.Header {
		for _, value := range values {
			outbound.Header.Add(name, value)
		}
	}

	for _, name := range hopHeaders {
		outbound.Header.Del(name)
	}

	for _, name := range clientHeaders {
		outbound.Header.Del(name)
	}

	for _, name := range auth.MethodOverrideHeaders {
		outbound.Header.Del(name)
	}

	// The forwarding headers are rewritten rather than passed on. pivot knows
	// what it saw; a client's own X-Forwarded-For is a claim, and appending to
	// it would let a customer prepend whatever it liked to the chain the
	// backend reads.
	outbound.Header.Del("X-Forwarded-For")
	outbound.Header.Del("X-Forwarded-Host")
	outbound.Header.Del("X-Forwarded-Proto")
	outbound.Header.Del("Forwarded")
}

// maybeCache stores a response when the backend allows it.
func (s *Server) maybeCache(
	ctx context.Context,
	key cache.Key,
	config rules.Cache,
	response *backendResponse,
	client app.Client,
) {
	storable, reason := cache.Storable(response.status, response.header, len(response.body))
	if !storable {
		s.log.Debug("not caching a response", "client", client.ID, "reason", reason)

		return
	}

	entry := cache.Entry{
		Status: response.status,
		Header: cache.FilterHeaders(response.header),
		Body:   response.body,
	}

	if err := s.state.Cache.Put(ctx, key, entry, config.TTL, config.Encrypt); err != nil {
		// Not a request failure: the response is already in hand, and the
		// only consequence is the next request going to the backend.
		s.log.Warn("could not cache a response", "client", client.ID, "error", err)
	}
}

// backendFailed ends a request the backend could not answer.
func (s *Server) backendFailed(
	ctx context.Context,
	w http.ResponseWriter,
	client app.Client,
	settings app.Settings,
	err error,
	result *outcome,
) {
	switch {
	case errors.Is(err, auth.ErrBackendRejected):
		// The backend refused pivot's own credentials. A distinct event,
		// because this will not fix itself: a rotated integration secret or a
		// revoked ACL role needs a person.
		result.status = http.StatusBadGateway

		s.log.Error("the backend rejected pivot's credentials",
			"client", client.ID, "error", err)
		// Stored unaggregated, unlike the others, and deliberately: the
		// backend rejecting pivot's own credentials is not something a
		// customer can cause in a loop, and it will not fix itself. One
		// record per occurrence is the right volume for a fault that needs a
		// person.
		s.state.Publish(ctx, app.BackendAuthFailed(client.ID, err))
		s.state.Audit.Security(ctx, client.ID, "backend.auth_failed", "", map[string]string{
			"error": err.Error(),
		})
		s.fail(w, result.status, "bad_gateway", "the backend rejected this request")

	case errors.Is(err, ErrNoSlot):
		// Every backend slot is busy. 503 with Retry-After, which is the
		// honest answer: the request was not wrong, pivot is protecting the
		// backend from it.
		result.status = http.StatusServiceUnavailable

		w.Header().Set(HeaderRetryAfter, "1")
		s.fail(w, result.status, "unavailable", "pivot is at its backend concurrency limit")

	case errors.Is(err, context.Canceled):
		// The customer's client went away. Nothing to write to.
		result.status = 499

	case errors.Is(err, context.DeadlineExceeded):
		result.status = http.StatusGatewayTimeout

		s.aggregator.BackendFailed(ctx, settings.BackendURL, err)
		s.fail(w, result.status, "gateway_timeout", "the backend did not answer in time")

	default:
		result.status = http.StatusBadGateway

		s.log.Error("the backend call failed", "client", client.ID, "error", err)
		s.aggregator.BackendFailed(ctx, settings.BackendURL, err)
		s.fail(w, result.status, "bad_gateway", "the backend could not be reached")
	}
}

// writeResponse sends a backend response to the client.
func (s *Server) writeResponse(w http.ResponseWriter, response *backendResponse, cacheStatus string) {
	header := w.Header()

	for name, values := range response.header {
		for _, value := range values {
			header.Add(name, value)
		}
	}

	for _, name := range hopHeaders {
		header.Del(name)
	}

	// Content-Length is set from what is actually being written rather than
	// from what the backend claimed: the two can differ if the backend lied,
	// and net/http would then either truncate or hang.
	header.Del("Content-Length")
	header.Set("Content-Length", strconv.Itoa(len(response.body)))
	header.Set(HeaderCacheStatus, cacheStatus)

	w.WriteHeader(response.status)
	_, _ = w.Write(response.body)
}

// writeEntry sends a cached response.
func (s *Server) writeEntry(w http.ResponseWriter, entry cache.Entry, cacheStatus string) {
	header := w.Header()

	for name, values := range entry.Header {
		for _, value := range values {
			header.Add(name, value)
		}
	}

	header.Set("Content-Length", strconv.Itoa(len(entry.Body)))
	header.Set(HeaderCacheStatus, cacheStatus)

	// Age tells a client how stale the answer is, which is the one thing it
	// cannot work out for itself and the difference between a cached response
	// and a dishonest one.
	if age := entry.Age(time.Now()); age > 0 {
		header.Set("Age", strconv.Itoa(int(age.Seconds())))
	}

	w.WriteHeader(entry.Status)
	_, _ = w.Write(entry.Body)
}

// handleToken answers pivot's own token endpoint.
//
// The shapes are RFC 6749's, which is also what Shopware returns, so a client
// that parsed the backend's token response parses pivot's unchanged - that is
// what transparent means here.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, settings app.Settings) int {
	ctx := r.Context()

	request, err := auth.ParseTokenRequest(r)
	if err != nil {
		if errors.Is(err, auth.ErrNoCredential) {
			auth.WriteError(w, http.StatusUnauthorized, auth.InvalidClient())

			return http.StatusUnauthorized
		}

		auth.WriteError(w, http.StatusBadRequest, auth.Error{
			Code:        auth.ErrorInvalidRequest,
			Description: "the token request is malformed",
		})

		return http.StatusBadRequest
	}

	if request.GrantType != auth.GrantClientCredentials {
		auth.WriteError(w, http.StatusBadRequest, auth.UnsupportedGrant(request.GrantType))

		return http.StatusBadRequest
	}

	client, err := s.state.Clients.Authenticate(ctx, request.ClientID, request.ClientSecret)
	if err != nil {
		s.log.Warn("authentication failed at the token endpoint",
			"client", request.ClientID,
			"reason", authFailureReason(err),
			"source", s.sourceFor(r, settings))
		s.aggregator.AuthFailed(ctx, request.ClientID, s.sourceFor(r, settings))

		auth.WriteError(w, http.StatusUnauthorized, auth.InvalidClient())

		return http.StatusUnauthorized
	}

	// The token endpoint is rate limited like any other request. It is the
	// one path an unauthenticated stranger can reach, so leaving it out would
	// make it the obvious place to guess secrets from.
	limit := client.RateLimit
	if limit.Unlimited() {
		limit = settings.DefaultRateLimit
	}

	decision, limitErr := s.state.Limiter.Allow(ctx, client.ID, limit)
	if limitErr == nil && !decision.Allowed {
		w.Header().Set(HeaderRetryAfter, strconv.Itoa(int(decision.RetryAfter.Seconds())))
		s.aggregator.RateLimited(ctx, client.ID)

		auth.WriteError(w, http.StatusTooManyRequests, auth.Error{
			Code:        auth.ErrorInvalidRequest,
			Description: "the client's rate limit has been exceeded",
		})

		return http.StatusTooManyRequests
	}

	value, token, err := s.state.Tokens.Issue(
		ctx, client.ID, "", request.Scope, client.ID, settings.TokenLifetime)
	if err != nil {
		s.log.Error("could not issue a token", "client", client.ID, "error", err)

		auth.WriteError(w, http.StatusInternalServerError, auth.Error{
			Code:        auth.ErrorServerError,
			Description: "the token could not be issued",
		})

		return http.StatusInternalServerError
	}

	s.log.Info("token issued",
		"client", client.ID,
		"expires_in", token.TTL(time.Now()).Round(time.Second).String())

	auth.WriteTokenResponse(w,
		auth.NewTokenResponse(value, settings.TokenLifetime, request.Scope))

	return http.StatusOK
}

// backendHost renders the backend origin for a log line, without its scheme.
func backendHost(url string) string {
	trimmed := strings.TrimPrefix(url, "https://")

	return strings.TrimPrefix(trimmed, "http://")
}
