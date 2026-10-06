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

// humanBytes renders a byte count for a table cell.
//
// Binary units, because that is what the limits are expressed in: a 64 MiB
// archive limit reported as "67.1 MB" invites an operator to think their 65 MB
// bundle should have fit.
func humanBytes(size int64) string {
	const unit = 1024

	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	value := float64(size)
	units := []string{"KiB", "MiB", "GiB", "TiB"}

	var suffix string

	for _, name := range units {
		value /= unit
		suffix = name

		if value < unit {
			break
		}
	}

	return fmt.Sprintf("%.1f %s", value, suffix)
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
