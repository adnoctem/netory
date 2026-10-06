package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client talks to an admin Server over its Unix socket.
//
// Every CLI subcommand except `secret generate` and `version` is a short-lived
// client of a running server, because the server is the only process allowed to
// open the database. The CLI therefore never touches the store directly, and
// Badger's exclusive directory lock means it could not even if the code tried.
type Client struct {
	path string
	http *http.Client
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// Path is the socket path to dial.
	Path string

	// Timeout bounds a whole request. Zero uses DefaultTimeout.
	Timeout time.Duration
}

// socketHost is the authority in the request URL. A Unix socket has no
// hostname, so this is a placeholder the server ignores; it exists because
// net/http requires a syntactically valid URL.
const socketHost = "admin"

// NewClient returns a Client dialling the given socket.
//
// It does not connect yet, so a Client can be built before the server is
// running. The connection failure surfaces on the first request, where there
// is a command to attribute it to.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Path == "" {
		return nil, errors.New("admin: socket path is required")
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	path := opts.Path

	return &Client{
		path: path,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// The address net/http computes from the URL is discarded: the
				// destination is a filesystem path, not a host and port.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", path)
				},

				// One admin command issues one or two requests and exits, so
				// connection pooling buys nothing and an idle pooled
				// connection would just delay process exit.
				DisableKeepAlives: true,
			},
		},
	}, nil
}

// Path returns the socket path this Client dials.
func (c *Client) Path() string { return c.path }

// Do sends a request and decodes a successful response into out.
//
// body is JSON-encoded when non-nil; out is skipped when nil. A non-2xx
// response is returned as an *Error carrying the server's message and hint, so
// the hint written by the handler is what the operator eventually reads.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("admin: encode request for %s %s: %w", method, path, err)
		}

		reader = bytes.NewReader(encoded)
	}

	target, err := requestURL(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return fmt.Errorf("admin: build request for %s %s: %w", method, path, err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return c.finish(req, method, path, out)
}

// finish sends a prepared request and decodes the response.
//
// Shared by Do and PostMultipart, which differ only in how they build the
// body: the error translation and the hint-preserving decode are the part that
// must not exist twice, because they are what turns a status code into
// something an operator can act on.
func (c *Client) finish(req *http.Request, method, path string, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return c.dialError(method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.responseError(resp)
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("admin: decode response for %s %s: %w", method, path, err)
	}

	return nil
}

// Get issues a GET and decodes the response.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post issues a POST with a JSON body.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPost, path, body, out)
}

// Put issues a PUT with a JSON body.
func (c *Client) Put(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPut, path, body, out)
}

// Delete issues a DELETE.
func (c *Client) Delete(ctx context.Context, path string) error {
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// Ping reports whether a server is reachable on the socket.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.path)
	if err != nil {
		return c.dialError(http.MethodGet, "", err)
	}

	return conn.Close()
}

// dialError turns a transport failure into something an operator can act on.
//
// "connection refused" and "no such file or directory" on an admin socket both
// mean the same thing in practice - the server is not running - and that is
// worth saying outright, because it is the single most common way these
// commands fail and the raw syscall error does not say it.
func (c *Client) dialError(method, path string, err error) error {
	var hint string
	switch {
	case errors.Is(err, os.ErrNotExist):
		hint = fmt.Sprintf("no socket at %s - is the server running?", c.path)
	case errors.Is(err, os.ErrPermission):
		hint = fmt.Sprintf(
			"the socket at %s is not readable by this user; admin access is granted by file permissions, so run as the service user or root",
			c.path,
		)
	case isConnectionRefused(err):
		hint = fmt.Sprintf("nothing is listening on %s - is the server running?", c.path)
	case errors.Is(err, context.DeadlineExceeded):
		hint = "the server accepted the connection but did not answer in time"
	default:
		hint = "could not reach the server on " + c.path
	}

	where := strings.TrimSpace(method + " " + path)
	if where == "" {
		where = "connect"
	}

	return &Error{
		Message: fmt.Sprintf("admin: %s: %v", where, err),
		Hint:    hint,
	}
}

// responseError reconstructs the server's *Error from a non-2xx response.
func (c *Client) responseError(resp *http.Response) error {
	payload, err := io.ReadAll(io.LimitReader(resp.Body, MaxRequestBytes))
	if err != nil {
		return &Error{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("admin: %s and the error body could not be read: %v", resp.Status, err),
		}
	}

	var decoded Error
	if err := json.Unmarshal(payload, &decoded); err == nil && decoded.Message != "" {
		decoded.Status = resp.StatusCode

		return &decoded
	}

	// Not a JSON error. net/http's own error pages land here, so the body is
	// reported but trimmed - it is not a message this repository wrote and may
	// be arbitrarily long.
	body := strings.TrimSpace(string(payload))
	if len(body) > 200 {
		body = body[:200] + "..."
	}

	message := "admin: " + resp.Status
	if body != "" {
		message += ": " + body
	}

	return &Error{Status: resp.StatusCode, Message: message}
}

// requestURL builds the absolute URL for a path that may carry a query string.
//
// The path and query are separated before being assigned, because url.URL
// escapes a "?" inside Path - so setting Path to "/v1/outbox?dead=true"
// produces "/v1/outbox%3Fdead=true" and the server sees the query as part of
// the path, matching no route at all. Splitting here is what makes every
// query-carrying admin call work.
func requestURL(path string) (string, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")

	target := &url.URL{Scheme: "http", Host: socketHost, Path: rawPath, RawQuery: rawQuery}

	// Parsed back to catch a path that cannot round-trip, rather than sending
	// something subtly different from what the caller asked for.
	if _, err := url.Parse(target.String()); err != nil {
		return "", fmt.Errorf("admin: %q is not a usable request path: %w", path, err)
	}

	return target.String(), nil
}

// isConnectionRefused reports whether err is ECONNREFUSED, without importing
// syscall into the portable part of this package.
func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}

	return strings.Contains(opErr.Err.Error(), "connection refused")
}
