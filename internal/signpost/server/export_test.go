package server

// Nothing is exported for tests here on purpose: the public mux and the admin
// mux are reachable through Server.PublicHandler and Server.AdminHandler,
// which are part of the package's API because `server start` is not the only
// thing that needs to drive them - and a test that reaches past them would be
// testing something the server does not actually serve.
