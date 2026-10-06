package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// Upload is one file part of a multipart request.
type Upload struct {
	// Field is the form field name the handler reads it from.
	Field string

	// Filename is sent with the part. Handlers treat it as a label only -
	// never as a path, and never as the thing that decides how the bytes are
	// interpreted.
	Filename string

	// Content is the bytes.
	Content []byte
}

// PostMultipart issues a multipart/form-data POST.
//
// This exists because DecodeJSON bounds a request at MaxRequestBytes, and some
// administrative requests carry a file that is legitimately much larger - a
// signpost bundle, for instance. Base64 inside a JSON document would work and
// would be the wrong shape: it inflates the payload by a third and makes the
// server buffer a string it then has to decode, when the thing being sent is
// already a sequence of bytes.
//
// The whole body is assembled in memory rather than streamed. The caller
// already holds the file - it read it from disk to hash it - so streaming
// would save nothing, and a buffer with a known length lets net/http set
// Content-Length instead of chunking.
func (c *Client) PostMultipart(
	ctx context.Context,
	path string,
	fields map[string]string,
	uploads []Upload,
	out any,
) error {
	var body bytes.Buffer

	writer := multipart.NewWriter(&body)

	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return fmt.Errorf("admin: write the %s field: %w", name, err)
		}
	}

	for _, upload := range uploads {
		part, err := writer.CreateFormFile(upload.Field, upload.Filename)
		if err != nil {
			return fmt.Errorf("admin: write the %s part: %w", upload.Field, err)
		}

		if _, err := part.Write(upload.Content); err != nil {
			return fmt.Errorf("admin: write the %s part: %w", upload.Field, err)
		}
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("admin: finish the multipart body: %w", err)
	}

	target, err := requestURL(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &body)
	if err != nil {
		return fmt.Errorf("admin: build request for POST %s: %w", path, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	return c.finish(req, http.MethodPost, path, out)
}

// MaxMultipartMemory is how much of a multipart body ParseUpload keeps in
// memory before spilling parts to temporary files.
//
// Deliberately larger than any part a netory service accepts, so nothing ever
// spills: a file written to /tmp is a file with different permissions and a
// different lifetime from everything else the service handles, and the point
// of an in-memory upload is that untrusted bytes never reach a filesystem at
// all.
const MaxMultipartMemory = 128 << 20 // 128 MiB

// ParseUpload reads a multipart request, bounding the whole body at limit.
//
// The limit is applied to the bytes actually read rather than to a declared
// Content-Length, which is the only version of the check that means anything:
// a declared length is a claim, and a body that keeps arriving past it is
// exactly the request worth stopping.
func ParseUpload(w http.ResponseWriter, r *http.Request, limit int64) (*multipart.Form, error) {
	if limit <= 0 {
		limit = MaxRequestBytes
	}

	r.Body = http.MaxBytesReader(w, r.Body, limit)

	if err := r.ParseMultipartForm(MaxMultipartMemory); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, Errorf(http.StatusRequestEntityTooLarge,
				"the request body is larger than the %d byte limit", limit)
		}

		return nil, Errorf(http.StatusBadRequest, "malformed upload: %v", err).
			WithHint("this is a bug in the CLI rather than something you can fix in the request")
	}

	return r.MultipartForm, nil
}

// UploadedFile returns the bytes of one file part.
//
// It reports ok rather than an error for a missing part, because optional
// parts are normal - a bundle may or may not come with a signature - and the
// caller distinguishes "absent" from "malformed" differently.
func UploadedFile(form *multipart.Form, field string) (name string, content []byte, ok bool, err error) {
	if form == nil {
		return "", nil, false, nil
	}

	headers, found := form.File[field]
	if !found || len(headers) == 0 {
		return "", nil, false, nil
	}

	if len(headers) > 1 {
		return "", nil, false, Errorf(http.StatusBadRequest,
			"the %s part was sent %d times, expected once", field, len(headers))
	}

	header := headers[0]

	file, err := header.Open()
	if err != nil {
		return "", nil, false, Errorf(http.StatusBadRequest,
			"could not read the %s part: %v", field, err)
	}
	defer func() { _ = file.Close() }()

	content, err = io.ReadAll(file)
	if err != nil {
		return "", nil, false, Errorf(http.StatusBadRequest,
			"could not read the %s part: %v", field, err)
	}

	return sanitiseFilename(header.Filename), content, true, nil
}

// UploadedField returns one text field of a multipart form.
func UploadedField(form *multipart.Form, field string) string {
	if form == nil {
		return ""
	}

	values, ok := form.Value[field]
	if !ok || len(values) == 0 {
		return ""
	}

	return strings.TrimSpace(values[0])
}

// sanitiseFilename reduces a client-supplied filename to something safe to log.
//
// A multipart filename is attacker-adjacent data even on a socket only the
// service user can reach: it ends up in an audit record, and a record that can
// carry a newline is a record that can be forged. Path separators go too, so
// nothing downstream can mistake the label for a location.
func sanitiseFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == '\\':
			return '_'
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, name)

	name = strings.TrimSpace(name)
	if len(name) > 128 {
		name = name[:128]
	}

	return name
}
