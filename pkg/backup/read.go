package backup

import (
	"fmt"
	"io"
)

// readAllBounded reads r in full, failing rather than allocating without limit
// once more than limit bytes have arrived.
//
// io.ReadAll on a remote body is unbounded, and the body here comes from
// whatever is in a bucket - which is not necessarily what protean put there.
// The limit is one byte over, so exceeding it is detectable rather than
// silently truncating, which would present as a corrupt backup.
func readAllBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, limit)
	}

	return data, nil
}
