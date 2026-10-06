package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// printJSON writes v as indented JSON, for `--json`.
func printJSON(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(v)
}

// table renders aligned columns.
//
// text/tabwriter rather than a dependency: the output is a handful of columns
// of short strings, which is precisely what the standard library's writer is
// for, and a table package would be a dependency for alignment alone.
type table struct {
	writer  *tabwriter.Writer
	columns int
}

// newTable starts a table with the given headers.
func newTable(w io.Writer, headers ...string) *table {
	t := &table{
		writer:  tabwriter.NewWriter(w, 0, 4, 3, ' ', 0),
		columns: len(headers),
	}

	// Headers are upper-cased, which is the convention every other CLI an
	// operator uses follows - kubectl, docker, systemctl.
	upper := make([]string, 0, len(headers))
	for _, header := range headers {
		upper = append(upper, strings.ToUpper(header))
	}

	t.row(upper...)

	return t
}

// row adds a row. Missing cells are padded and extra cells dropped, so a
// mismatch cannot produce a ragged table.
func (t *table) row(cells ...string) {
	for len(cells) < t.columns {
		cells = append(cells, "")
	}

	fmt.Fprintln(t.writer, strings.Join(cells[:t.columns], "\t"))
}

// flush writes the table.
func (t *table) flush() error { return t.writer.Flush() }

// renderSettings formats a settings map as sorted "key=value" lines, for the
// detail column of a list.
//
// Sorted so that two runs of the same command produce identical output, which
// is what makes the output diffable.
func renderSettings(settings map[string]string) string {
	if len(settings) == 0 {
		return "-"
	}

	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+settings[key])
	}

	return strings.Join(parts, " ")
}

// dash renders an empty string as "-", so a table column is never blank and a
// missing value is visibly missing rather than ambiguous.
func dash(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

// sortedKeys returns a map's keys in order, so repeated runs of a command
// produce identical output and the result is diffable.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// shortDuration renders an age compactly, for a table cell.
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// splitAndTrim splits a comma-separated list and trims each entry.
func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}

	return out
}

// parseSettings turns repeated --set key=value flags into a map.
func parseSettings(entries []string) (map[string]string, error) {
	settings := make(map[string]string, len(entries))

	for _, entry := range entries {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("--set %q is not key=value", entry)
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("--set %q has an empty key", entry)
		}

		// The value is not trimmed: a credential could legitimately end in
		// whitespace, and silently altering one would be a maddening bug to
		// track down.
		if _, duplicate := settings[key]; duplicate {
			return nil, fmt.Errorf("--set %s given more than once", key)
		}

		settings[key] = value
	}

	return settings, nil
}
