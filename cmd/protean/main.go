// Command protean is a self-hosted dynDNS control plane.
//
// This is a thin entrypoint: the command tree lives in
// internal/protean/cmd and the application state in internal/protean/app.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/adnoctem/netory/internal/protean/cmd"
	"github.com/adnoctem/netory/pkg/admin"

	// Imported for its link-time variables, which Bazel's x_defs populate.
	_ "github.com/adnoctem/netory/pkg/stamp"
)

func main() {
	root := cmd.NewRootCommand()

	if err := root.ExecuteContext(context.Background()); err != nil {
		// The message and the hint are printed separately: the message says
		// what went wrong, the hint says what to do about it, and running them
		// together makes both harder to read.
		fmt.Fprintf(os.Stderr, "error: %v\n", err)

		if hint := admin.HintFor(err); hint != "" {
			fmt.Fprintf(os.Stderr, "hint: %s\n", hint)
		}

		os.Exit(exitCodeFor(err))
	}
}

// exitCodeFor maps an error onto an exit status.
//
// Distinguishing "the server is not running" from "the request was rejected"
// lets a deployment script tell a service that is down from a command that was
// wrong, which is the difference between retrying and giving up.
func exitCodeFor(err error) int {
	var adminErr *admin.Error
	if errors.As(err, &adminErr) {
		switch {
		case adminErr.Status == 0:
			// No HTTP status: the request never reached a server.
			return 3
		case adminErr.Status >= 500:
			return 2
		default:
			return 1
		}
	}

	return 1
}
