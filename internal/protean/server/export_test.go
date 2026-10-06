package server

import (
	"net/http"

	"github.com/adnoctem/netory/internal/protean/app"
)

// Compiled only into the test binary: the handlers can be driven with
// httptest without exporting the mux builders, which no production caller
// needs.

// UpdateHandlerForTest returns the network-facing handler.
func UpdateHandlerForTest(state *app.State) (http.Handler, error) {
	s, err := newForTest(state)
	if err != nil {
		return nil, err
	}

	return s.updateHandler(), nil
}

// AdminHandlerForTest returns the admin handler.
func AdminHandlerForTest(state *app.State) (http.Handler, error) {
	s, err := newForTest(state)
	if err != nil {
		return nil, err
	}

	return s.adminHandler(), nil
}

// newForTest builds the parts of Server the handlers need, without opening
// either listener - binding a socket and a TCP port is not what these tests
// are about.
func newForTest(state *app.State) (*Server, error) {
	return &Server{
		state:   state,
		log:     state.Log,
		source:  NewSourceResolver(state.Config),
		limiter: NewLimiter(state.RateLimit),
	}, nil
}
