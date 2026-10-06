package server

import (
	"errors"

	"github.com/adnoctem/netory/pkg/backup"
)

// isBackupNotFound and isBackupTooLarge keep the sentinel checks in one place,
// so the admin handlers do not each import pkg/backup to classify an error.
func isBackupNotFound(err error) bool { return errors.Is(err, backup.ErrNotFound) }

func isBackupTooLarge(err error) bool { return errors.Is(err, backup.ErrTooLarge) }
