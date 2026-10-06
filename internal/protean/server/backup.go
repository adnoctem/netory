package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/backup"
)

// backupTimeout bounds a backup or a verification.
//
// Generous, because it covers a snapshot of the whole database plus an upload
// to S3 over whatever link the host has - but bounded, so a wedged upload does
// not hold an admin connection for the life of the process.
const backupTimeout = 15 * time.Minute

// BackupResult is the result of `backup create`.
//
// Aliased from the app package rather than redeclared, so the CLI has one
// import for every admin payload and the two cannot drift apart.
type BackupResult = app.BackupResult

// BackupRequest is the body of `backup create`, `backup list` and
// `backup verify`.
type BackupRequest struct {
	// Destination is a filesystem path or an s3://bucket/prefix location.
	Destination string `json:"destination"`

	// Name identifies a stored backup, for verify.
	Name string `json:"name,omitempty"`
}

// BackupListResponse is the result of `backup list`.
type BackupListResponse struct {
	Destination string         `json:"destination"`
	Entries     []backup.Entry `json:"entries"`
}

// BackupVerifyResponse is the result of `backup verify`.
type BackupVerifyResponse struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	OK          bool   `json:"ok"`
	PlainSize   int64  `json:"plain_size,omitempty"`
	Message     string `json:"message"`
}

// adminBackupCreate takes a backup of the live database.
//
// The server does the work rather than streaming the database out through the
// admin socket for the CLI to upload. Two reasons: the server is the process
// with an instance or task role, so S3 credentials are already where they need
// to be, and a plaintext snapshot of every credential in the database has no
// business crossing a socket when it does not have to.
func (s *Server) adminBackupCreate(w http.ResponseWriter, r *http.Request) {
	var req BackupRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	if strings.TrimSpace(req.Destination) == "" {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "a destination is required").
			WithHint("pass a directory path, or an s3://bucket/prefix location"))

		return
	}

	// A timeout of protean's own, not the request's: an operator pressing
	// Ctrl-C should not abandon a half-finished upload, and a stalled
	// destination must not hold the socket open indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), backupTimeout)
	defer cancel()

	result, err := s.state.Backup(ctx, req.Destination)
	if err != nil {
		admin.WriteError(w, s.translateBackup(err))

		return
	}

	admin.WriteJSON(w, http.StatusCreated, result)
}

func (s *Server) adminBackupList(w http.ResponseWriter, r *http.Request) {
	destination := strings.TrimSpace(r.URL.Query().Get("destination"))
	if destination == "" {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "a destination is required").
			WithHint("pass a directory path, or an s3://bucket/prefix location"))

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTimeout)
	defer cancel()

	entries, described, err := s.state.ListBackups(ctx, destination)
	if err != nil {
		admin.WriteError(w, s.translateBackup(err))

		return
	}

	if entries == nil {
		entries = []backup.Entry{}
	}

	admin.WriteJSON(w, http.StatusOK, BackupListResponse{Destination: described, Entries: entries})
}

// adminBackupVerify confirms a stored backup decrypts, without restoring it.
//
// A backup nobody has ever opened is a backup nobody knows works, and an
// incident is the wrong moment to find out.
func (s *Server) adminBackupVerify(w http.ResponseWriter, r *http.Request) {
	var req BackupRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	if strings.TrimSpace(req.Destination) == "" || strings.TrimSpace(req.Name) == "" {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest,
			"a destination and a name are required").
			WithHint("run `protean backup list --at <destination>` to see the stored names"))

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTimeout)
	defer cancel()

	size, err := s.state.VerifyBackup(ctx, req.Destination, req.Name)
	if err != nil {
		// A backup that will not open is reported as a failed verification
		// rather than as a request error: the request was fine, the backup is
		// the problem, and that distinction is the whole point of verifying.
		admin.WriteJSON(w, http.StatusOK, BackupVerifyResponse{
			Name:        req.Name,
			Destination: req.Destination,
			OK:          false,
			Message:     err.Error(),
		})

		return
	}

	admin.WriteJSON(w, http.StatusOK, BackupVerifyResponse{
		Name:        req.Name,
		Destination: req.Destination,
		OK:          true,
		PlainSize:   size,
		Message:     "decrypts under this server's secret and is intact",
	})
}

// translateBackup maps backup errors onto admin errors with a hint.
func (s *Server) translateBackup(err error) error {
	switch {
	case isBackupNotFound(err):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `protean backup list --at <destination>` to see the stored names")
	case isBackupTooLarge(err):
		return admin.Errorf(http.StatusInsufficientStorage, "%v", err).
			WithHint("the notification outbox is the usual cause; check `protean outbox status --dead`")
	default:
		return err
	}
}
