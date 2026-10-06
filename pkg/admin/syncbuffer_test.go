package admin_test

import (
	"strings"
	"sync"
)

// syncBuffer is a concurrency-safe io.Writer for capturing audit output. The
// admin server writes records from its own goroutines while a test reads them.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
