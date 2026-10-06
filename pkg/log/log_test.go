package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFormat(t *testing.T) {
	asrt := assert.New(t)

	for _, in := range []string{"json", "JSON", " json "} {
		f, ok := ParseFormat(in)
		asrt.True(ok, in)
		asrt.Equal(FormatJSON, f, in)
	}

	f, ok := ParseFormat("logfmt")
	asrt.False(ok)
	asrt.Equal(FormatText, f, "an unknown format must still resolve to a usable default")
}

func TestParseLevel(t *testing.T) {
	asrt := assert.New(t)

	for in, want := range map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"ERROR":   slog.LevelError,
	} {
		l, ok := ParseLevel(in)
		asrt.True(ok, in)
		asrt.Equal(want, l, in)
	}

	l, ok := ParseLevel("trace")
	asrt.False(ok)
	asrt.Equal(slog.LevelInfo, l)
}

func TestJSONFormatAndBaseAttrs(t *testing.T) {
	asrt := assert.New(t)

	var buf bytes.Buffer
	lgr := New(
		WithOutput(&buf),
		WithFormat(FormatJSON),
		WithAttrs(slog.String("service", "protean")),
	)
	lgr.Info("listening", "addr", ":8443")

	var rec map[string]any
	asrt.NoError(json.Unmarshal(buf.Bytes(), &rec))
	asrt.Equal("listening", rec["msg"])
	asrt.Equal("protean", rec["service"])
	asrt.Equal(":8443", rec["addr"])
}

func TestLevelFiltering(t *testing.T) {
	asrt := assert.New(t)

	var buf bytes.Buffer
	lgr := New(WithOutput(&buf), WithLevel(slog.LevelWarn))

	lgr.Info("dropped")
	asrt.Empty(buf.String())

	lgr.Warn("kept")
	asrt.Contains(buf.String(), "kept")
}

// A level change must reach loggers derived before the change, or a per-request
// child logger would keep the level its parent had at request start.
func TestSetLevelPropagatesToDerivedLoggers(t *testing.T) {
	asrt := assert.New(t)

	var buf bytes.Buffer
	parent := New(WithOutput(&buf), WithLevel(slog.LevelInfo))
	child := parent.With("host", "example.org")

	child.Debug("dropped")
	asrt.Empty(buf.String())

	parent.SetLevel(slog.LevelDebug)
	asrt.Equal(slog.LevelDebug, child.Level())

	child.Debug("kept")
	asrt.Contains(buf.String(), "kept")
	asrt.Contains(buf.String(), "example.org")
}

func TestWithGroupNestsAttributes(t *testing.T) {
	asrt := assert.New(t)

	var buf bytes.Buffer
	lgr := New(WithOutput(&buf), WithFormat(FormatJSON)).WithGroup("request")
	lgr.Info("handled", "method", "GET")

	var rec map[string]any
	asrt.NoError(json.Unmarshal(buf.Bytes(), &rec))
	group, isMap := rec["request"].(map[string]any)
	asrt.True(isMap, "WithGroup must nest the attributes under its name")
	asrt.Equal("GET", group["method"])
}

// SetLevel is documented as safe to call while the Logger is in use; this is
// the assertion behind that sentence under -race.
func TestConcurrentLoggingAndLevelChange(t *testing.T) {
	var mu sync.Mutex
	lgr := New(WithOutput(&lockedWriter{mu: &mu}))

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				lgr.Info("concurrent")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 50 {
			if i%2 == 0 {
				lgr.SetLevel(slog.LevelDebug)
			} else {
				lgr.SetLevel(slog.LevelWarn)
			}
		}
	}()
	wg.Wait()
}

// lockedWriter serialises writes so the test exercises the Logger rather than
// a concurrently-appended bytes.Buffer.
type lockedWriter struct {
	mu  *sync.Mutex
	buf strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.buf.Write(p)
}

func TestDefaultIsStable(t *testing.T) {
	assert.Same(t, Default(), Default(), "Default must return the same Logger on every call")
}
