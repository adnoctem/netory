package cmd

import "net/url"

// urlQueryEscape escapes a value for a query string.
//
// A client id is generated hex and needs no escaping, but the admin client
// splits a path on "?" to build its request - so a value interpolated raw
// would be a way for an identifier to add query parameters of its own.
func urlQueryEscape(value string) string { return url.QueryEscape(value) }
