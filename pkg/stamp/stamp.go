// Package stamp carries build metadata injected at link time. Every value
// defaults to "redacted" so an unstamped build - `go run`, `go test`, an
// editor's build - still produces well-formed output instead of empty strings.
//
// The values are populated by Bazel through go_library x_defs, which read the
// keys emitted by scripts/status.sh via --workspace_status_command. Adding a
// stamp means adding the variable here, the x_defs entry in BUILD.bazel, and
// the key in status.sh; miss one and the value silently stays "redacted".
package stamp

var (
	Version   = "redacted"
	BuildDate = "redacted"
	CommitSHA = "redacted"
	Branch    = "redacted"
	Platform  = "redacted"
	GoVersion = "redacted"
)

// Stamps is a snapshot of the link-time values, suitable for embedding in an
// application struct or marshalling into `<app> version` output.
type Stamps struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	CommitSHA string `json:"commit_sha"`
	Branch    string `json:"branch"`
	Platform  string `json:"platform"`
	GoVersion string `json:"go_version"`
}

// New returns a Stamps snapshot of the current link-time values.
func New() *Stamps {
	return &Stamps{
		Version:   Version,
		BuildDate: BuildDate,
		CommitSHA: CommitSHA,
		Branch:    Branch,
		Platform:  Platform,
		GoVersion: GoVersion,
	}
}
