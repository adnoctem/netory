package cmd

import "net/url"

// urlQueryEscape escapes a value for a query string.
//
// Destinations contain "/" and ":" - an s3:// location especially - so they
// cannot be interpolated raw.
func urlQueryEscape(value string) string { return url.QueryEscape(value) }
