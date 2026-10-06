package app

import "sort"

// sortHosts orders hosts by name.
func sortHosts(hosts []Host) {
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
}

// sortTokens orders tokens by host and then creation time, so `token list`
// groups a host's tokens together with the oldest first - which is the order an
// operator rotating them wants to read.
func sortTokens(tokens []Token) {
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].Host != tokens[j].Host {
			return tokens[i].Host < tokens[j].Host
		}

		return tokens[i].CreatedAt.Before(tokens[j].CreatedAt)
	})
}
