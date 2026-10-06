package admin_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/admin"
)

// uploadEcho reports back what it received, so a test can assert on the
// server's view of the request rather than on the client's.
type uploadEcho struct {
	Fields   map[string]string `json:"fields"`
	Filename string            `json:"filename"`
	Size     int               `json:"size"`
	Content  string            `json:"content"`
	HadExtra bool              `json:"had_extra"`
}

// uploadMux is a handler that reads a multipart request through ParseUpload.
func uploadMux(limit int64) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		form, err := admin.ParseUpload(w, r, limit)
		if err != nil {
			admin.WriteError(w, err)

			return
		}
		defer func() {
			if form != nil {
				_ = form.RemoveAll()
			}
		}()

		name, content, ok, err := admin.UploadedFile(form, "archive")
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		if !ok {
			admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "no archive part"))

			return
		}

		_, _, extra, err := admin.UploadedFile(form, "signature")
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		admin.WriteJSON(w, http.StatusOK, uploadEcho{
			Fields: map[string]string{
				"release": admin.UploadedField(form, "release"),
				"missing": admin.UploadedField(form, "missing"),
			},
			Filename: name,
			Size:     len(content),
			Content:  string(content),
			HadExtra: extra,
		})
	})

	return mux
}

func TestPostMultipart(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(0))

	var echo uploadEcho
	require.NoError(t, h.client.PostMultipart(context.Background(), "/upload",
		map[string]string{"release": "1.4.0"},
		[]admin.Upload{
			{Field: "archive", Filename: "bundle.tar.gz", Content: []byte("archive bytes")},
			{Field: "signature", Filename: "bundle.tar.gz.minisig", Content: []byte("sig")},
		},
		&echo))

	asrt := assert.New(t)
	asrt.Equal("1.4.0", echo.Fields["release"])
	asrt.Empty(echo.Fields["missing"], "an absent field reads as empty, not as an error")
	asrt.Equal("bundle.tar.gz", echo.Filename)
	asrt.Equal("archive bytes", echo.Content)
	asrt.True(echo.HadExtra)
}

// A body larger than the limit is refused on the bytes actually read, not on a
// declared Content-Length: a declared length is a claim, and a body that keeps
// arriving past it is exactly the request worth stopping.
func TestParseUploadEnforcesTheLimit(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(1024))

	err := h.client.PostMultipart(context.Background(), "/upload", nil,
		[]admin.Upload{{Field: "archive", Filename: "big", Content: bytes.Repeat([]byte("x"), 4096)}},
		nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)

	assert.Equal(t, http.StatusRequestEntityTooLarge, adminErr.Status)
}

// An upload just under the limit still works, so the limit is a limit rather
// than a smaller limit than advertised.
func TestParseUploadAcceptsUpToTheLimit(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(64<<10))

	var echo uploadEcho
	require.NoError(t, h.client.PostMultipart(context.Background(), "/upload", nil,
		[]admin.Upload{{Field: "archive", Filename: "ok", Content: bytes.Repeat([]byte("y"), 32<<10)}},
		&echo))

	assert.Equal(t, 32<<10, echo.Size)
}

func TestParseUploadRejectsANonMultipartBody(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(0))

	err := h.client.Post(context.Background(), "/upload", map[string]string{"not": "multipart"}, nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)

	assert.Equal(t, http.StatusBadRequest, adminErr.Status)
	assert.Contains(t, adminErr.Hint, "bug in the CLI")
}

// A multipart filename is attacker-adjacent data even on a socket only the
// service user can reach: it ends up in an audit record, and a record a client
// can inject a newline into is a record a client can forge.
func TestUploadedFilenameIsSanitised(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(0))

	for label, filename := range map[string]string{
		"path separators": "../../etc/passwd",
		"a newline":       "bundle\n2026-01-01 forged audit line",
		"a NUL":           "bundle\x00.tar.gz",
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			var echo uploadEcho

			err := h.client.PostMultipart(context.Background(), "/upload", nil,
				[]admin.Upload{{Field: "archive", Filename: filename, Content: []byte("x")}},
				&echo)

			// Either the MIME parser refuses the header outright - which a NUL
			// byte gets - or the filename comes back harmless. Both are
			// acceptable; what is not is a hostile name reaching an audit
			// record intact.
			if err != nil {
				var adminErr *admin.Error
				require.ErrorAs(t, err, &adminErr)
				assert.Equal(t, http.StatusBadRequest, adminErr.Status)

				return
			}

			asrt := assert.New(t)
			asrt.NotContains(echo.Filename, "/")
			asrt.NotContains(echo.Filename, "\\")
			asrt.NotContains(echo.Filename, "\n")
			asrt.NotContains(echo.Filename, "\x00")
		})
	}
}

func TestUploadedFilenameIsBounded(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(0))

	var echo uploadEcho
	require.NoError(t, h.client.PostMultipart(context.Background(), "/upload", nil,
		[]admin.Upload{{Field: "archive", Filename: strings.Repeat("a", 4096), Content: []byte("x")}},
		&echo))

	assert.LessOrEqual(t, len(echo.Filename), 128)
}

// One part sent twice is rejected rather than having one silently win: which
// of two archives was published is not a question anyone should have to ask.
func TestUploadedFileRejectsARepeatedPart(t *testing.T) {
	t.Parallel()

	h := newHarness(t, uploadMux(0))

	err := h.client.PostMultipart(context.Background(), "/upload", nil,
		[]admin.Upload{
			{Field: "archive", Filename: "one", Content: []byte("first")},
			{Field: "archive", Filename: "two", Content: []byte("second")},
		},
		nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)

	assert.Equal(t, http.StatusBadRequest, adminErr.Status)
	assert.Contains(t, adminErr.Message, "sent 2 times")
}

func TestUploadHelpersOnANilForm(t *testing.T) {
	t.Parallel()

	// Defensive, but the handlers above all guard on an error before touching
	// the form, and a nil form reaching them would otherwise panic on the
	// public listener's sibling.
	var form *multipart.Form

	name, content, ok, err := admin.UploadedFile(form, "archive")
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.Empty(name)
	asrt.Nil(content)
	asrt.False(ok)
	asrt.Empty(admin.UploadedField(form, "release"))
}
