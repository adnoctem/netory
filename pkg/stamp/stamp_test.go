package stamp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSnapshotsLinkTimeValues(t *testing.T) {
	asrt := assert.New(t)

	s := New()
	asrt.Equal(Version, s.Version)
	asrt.Equal(BuildDate, s.BuildDate)
	asrt.Equal(CommitSHA, s.CommitSHA)
	asrt.Equal(Branch, s.Branch)
	asrt.Equal(Platform, s.Platform)
	asrt.Equal(GoVersion, s.GoVersion)
}

// An unstamped build must still produce usable output rather than empty
// strings, since `<app> version` runs in exactly that configuration under
// `go test` and `go run`.
func TestDefaultsAreNotEmpty(t *testing.T) {
	asrt := assert.New(t)

	s := New()

	// Logged so that `bazel test //pkg/stamp:stamp_test --stamp
	// --test_output=all -- -test.v` shows what the workspace status command
	// actually substituted. There is no assertion on the stamped values: the
	// same test has to pass in an unstamped `go test` run.
	t.Logf("version=%q build_date=%q commit=%q branch=%q platform=%q go=%q",
		s.Version, s.BuildDate, s.CommitSHA, s.Branch, s.Platform, s.GoVersion)

	asrt.NotEmpty(s.Version)
	asrt.NotEmpty(s.BuildDate)
	asrt.NotEmpty(s.CommitSHA)
	asrt.NotEmpty(s.Branch)
	asrt.NotEmpty(s.Platform)
	asrt.NotEmpty(s.GoVersion)
}
