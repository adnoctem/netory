package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
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
