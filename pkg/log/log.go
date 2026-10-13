// Package log wraps log/slog with the small amount of configuration the netory
// services need: a selectable output format, a level that can be changed at
// runtime, and a base set of attributes.
//
// It deliberately adds no dependency. All three services write structured
// audit records,
// and slog's attribute model covers that natively, so there is nothing a
// third-party logger would buy here.
package log

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Format selects the encoding of a log record.
type Format string

const (
	// FormatText is logfmt-style key=value output, intended for a terminal.
	FormatText Format = "text"

	// FormatJSON is one JSON object per record, intended for a log collector.
	// This is the right choice for a long-running server and for anything an
	// auditor is expected to query.
	FormatJSON Format = "json"
)

// ParseFormat resolves a configuration string to a Format. Unknown values
// resolve to FormatText together with an ok=false report, so a caller can
// decide between rejecting the configuration and falling back.
func ParseFormat(s string) (f Format, ok bool) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, true
	case FormatJSON:
		return FormatJSON, true
	default:
		return FormatText, false
	}
}

// ParseLevel resolves a configuration string to a slog.Level. Unknown values
// resolve to slog.LevelInfo together with an ok=false report.
func ParseLevel(s string) (l slog.Level, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// Logger embeds *slog.Logger, so it assumes the whole slog API, and adds a
// level that can be moved after construction.
type Logger struct {
	*slog.Logger

	// level is held as a *slog.LevelVar rather than a slog.Level so that
	// `<app> config set log.level` can take effect on a running server without
	// rebuilding the handler. slog.LevelVar is safe for concurrent use, which
	// is what makes this sound while requests are in flight.
	level *slog.LevelVar
}

// options is the resolved configuration for a Logger.
type options struct {
	level     slog.Level
	format    Format
	output    io.Writer
	addSource bool
	attrs     []slog.Attr
}

// Option configures a Logger during New.
type Option func(*options)

// WithLevel sets the initial minimum level. It can be changed afterwards
// through Logger.SetLevel.
func WithLevel(l slog.Level) Option {
	return func(o *options) { o.level = l }
}

// WithFormat selects the record encoding.
func WithFormat(f Format) Option {
	return func(o *options) { o.format = f }
}

// WithOutput redirects records to w. The default is os.Stderr, not os.Stdout:
// the CLI subcommands write their actual results to stdout, and mixing
// diagnostics into that stream would break piping `<app> host list` into
// another process.
func WithOutput(w io.Writer) Option {
	return func(o *options) { o.output = w }
}

// WithSource includes the calling file and line in every record. Useful while
// developing, expensive enough to leave off by default.
func WithSource(enabled bool) Option {
	return func(o *options) { o.addSource = enabled }
}

// WithAttrs adds attributes to every record, for example the service name and
// version. Repeated calls accumulate.
func WithAttrs(attrs ...slog.Attr) Option {
	return func(o *options) { o.attrs = append(o.attrs, attrs...) }
}

// New builds a Logger. It cannot fail: every Option resolves to a valid value,
// and an unrecognised Format is rejected at parse time rather than here.
func New(opts ...Option) *Logger {
	o := &options{
		level:  slog.LevelInfo,
		format: FormatText,
		output: os.Stderr,
	}
	for _, opt := range opts {
		opt(o)
	}

	level := new(slog.LevelVar)
	level.Set(o.level)

	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: o.addSource,
	}

	var handler slog.Handler
	switch o.format {
	case FormatJSON:
		handler = slog.NewJSONHandler(o.output, handlerOpts)
	default:
		handler = slog.NewTextHandler(o.output, handlerOpts)
	}

	if len(o.attrs) > 0 {
		handler = handler.WithAttrs(o.attrs)
	}

	return &Logger{
		Logger: slog.New(handler),
		level:  level,
	}
}

// SetLevel changes the minimum level of an existing Logger. It is safe to call
// while the Logger is in use.
func (l *Logger) SetLevel(level slog.Level) { l.level.Set(level) }

// Level reports the current minimum level.
func (l *Logger) Level() slog.Level { return l.level.Level() }

// With returns a Logger that adds attrs to every record, sharing this Logger's
// level. Sharing is the point: a per-request child logger must follow a
// runtime level change made on its parent.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger: l.Logger.With(args...),
		level:  l.level,
	}
}

// WithGroup returns a Logger that nests subsequent attributes under name,
// sharing this Logger's level.
func (l *Logger) WithGroup(name string) *Logger {
	return &Logger{
		Logger: l.Logger.WithGroup(name),
		level:  l.level,
	}
}

// Default returns a process-wide Logger for the narrow window before
// configuration is available - a failure while parsing flags, for instance.
//
// It is built once and never replaced. gopskit's pkg/log exposes a mutable
// `Global` that init assigns and callers may reassign; a package-level
// variable holding a logger that other goroutines are already writing through
// is a data race waiting for a second assignment, so there is no setter here.
// Application code takes its Logger from the app struct instead.
var Default = sync.OnceValue(func() *Logger { return New() })
