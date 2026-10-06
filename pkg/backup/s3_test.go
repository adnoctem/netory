package backup_test

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/backup"
)

// fakeS3 is a minimal S3 server: enough of PutObject, GetObject and
// ListObjectsV2 for the real AWS SDK to talk to.
//
// Worth the hundred lines. The alternative is shipping the S3 destination
// without ever having run it, and the parts that go wrong - the key prefix
// handling, the XML listing, the path-style addressing - are exactly the parts
// a unit test over a mocked client would not touch.
type fakeS3 struct {
	server *httptest.Server

	mu      sync.Mutex
	objects map[string][]byte
	puts    []string
}

// listBucketResult is the ListObjectsV2 response shape.
type listBucketResult struct {
	XMLName  xml.Name     `xml:"ListBucketResult"`
	Name     string       `xml:"Name"`
	Prefix   string       `xml:"Prefix"`
	KeyCount int          `xml:"KeyCount"`
	Contents []listObject `xml:"Contents"`
}

type listObject struct {
	Key          string    `xml:"Key"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()

	f := &fakeS3{objects: map[string][]byte{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)

	// Credentials and a region, so the SDK's signer is satisfied. The fake
	// ignores the signature; the point is to exercise protean's code and the
	// SDK's request shaping, not to re-test SigV4.
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "eu-central-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv(backup.EnvS3Endpoint, f.server.URL)
	t.Setenv(backup.EnvS3PathStyle, "true")

	return f
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	// Path-style addressing: /bucket/key...
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(trimmed, "/")

	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		f.list(w, bucket, r.URL.Query().Get("prefix"))
	case r.Method == http.MethodPut:
		f.put(w, r, key)
	case r.Method == http.MethodGet:
		f.get(w, key)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeS3) put(w http.ResponseWriter, r *http.Request, key string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	f.mu.Lock()
	f.objects[key] = body
	f.puts = append(f.puts, key)
	f.mu.Unlock()

	w.Header().Set("ETag", `"fake"`)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) get(w http.ResponseWriter, key string) {
	f.mu.Lock()
	body, ok := f.objects[key]
	f.mu.Unlock()

	if !ok {
		// The SDK maps this to types.NoSuchKey, which is what the destination
		// turns into backup.ErrNotFound.
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(
			`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`))

		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (f *fakeS3) list(w http.ResponseWriter, bucket, prefix string) {
	f.mu.Lock()
	result := listBucketResult{Name: bucket, Prefix: prefix}

	for key, body := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		result.Contents = append(result.Contents, listObject{
			Key:          key,
			Size:         int64(len(body)),
			LastModified: time.Now().UTC(),
		})
	}
	f.mu.Unlock()

	result.KeyCount = len(result.Contents)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(result)
}

func (f *fakeS3) putKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.puts...)
}

func TestS3DestinationRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := newFakeS3(t)

	dest, err := backup.Open(ctx, "s3://backups/protean/prod")
	require.NoError(t, err)
	asrt.Equal("s3://backups/protean/prod", dest.Describe())

	entries, err := dest.List(ctx)
	asrt.NoError(err)
	asrt.Empty(entries, "an empty prefix lists nothing rather than erroring")

	name := backup.Name("protean", "1.0.0", time.Now())
	require.NoError(t, dest.Put(ctx, name, []byte("sealed-contents")))

	// The key is the prefix plus the name, with exactly one separator.
	keys := fake.putKeys()
	require.Len(t, keys, 1)
	asrt.Equal("protean/prod/"+name, keys[0])

	got, err := dest.Get(ctx, name)
	asrt.NoError(err)
	asrt.Equal("sealed-contents", string(got))

	entries, err = dest.List(ctx)
	asrt.NoError(err)
	require.Len(t, entries, 1)

	// The listing reports the name relative to the prefix, so it is the same
	// name Get and the CLI take.
	asrt.Equal(name, entries[0].Name)
	asrt.Equal(int64(len("sealed-contents")), entries[0].Size)
}

// A destination with no prefix must not produce a leading slash in the key.
func TestS3DestinationWithoutAPrefix(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := newFakeS3(t)

	dest, err := backup.Open(ctx, "s3://backups")
	require.NoError(t, err)
	asrt.Equal("s3://backups", dest.Describe())

	name := backup.Name("protean", "1.0.0", time.Now())
	require.NoError(t, dest.Put(ctx, name, []byte("contents")))

	keys := fake.putKeys()
	require.Len(t, keys, 1)
	asrt.Equal(name, keys[0], "no prefix means no leading separator")

	entries, err := dest.List(ctx)
	asrt.NoError(err)
	require.Len(t, entries, 1)
	asrt.Equal(name, entries[0].Name)
}

// Trailing and doubled slashes in the destination must all mean the same place,
// because an operator will write them inconsistently.
func TestS3PrefixNormalisation(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	for _, raw := range []string{
		"s3://backups/protean",
		"s3://backups/protean/",
		"s3://backups//protean//",
	} {
		fake := newFakeS3(t)

		dest, err := backup.Open(ctx, raw)
		require.NoError(t, err, raw)

		require.NoError(t, dest.Put(ctx, "protean-20261009T120000Z-1.0.0.backup", []byte("x")), raw)

		keys := fake.putKeys()
		require.Len(t, keys, 1, raw)
		asrt.Equal("protean/protean-20261009T120000Z-1.0.0.backup", keys[0], raw)
	}
}

func TestS3GetMissingIsNotFound(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	newFakeS3(t)

	dest, err := backup.Open(ctx, "s3://backups/protean")
	require.NoError(t, err)

	_, err = dest.Get(ctx, "protean-20261009T120000Z-1.0.0.backup")
	asrt.ErrorIs(err, backup.ErrNotFound)
}

// Objects that are not protean backups must be ignored rather than listed: a
// bucket is frequently shared.
func TestS3ListIgnoresForeignObjects(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := newFakeS3(t)

	dest, err := backup.Open(ctx, "s3://backups/protean")
	require.NoError(t, err)

	name := backup.Name("protean", "1.0.0", time.Now())
	require.NoError(t, dest.Put(ctx, name, []byte("contents")))

	// Planted directly, bypassing Put's name validation.
	fake.mu.Lock()
	fake.objects["protean/notes.txt"] = []byte("hello")
	fake.objects["protean/nested/other.backup"] = []byte("nested")
	fake.mu.Unlock()

	entries, err := dest.List(ctx)
	asrt.NoError(err)
	require.Len(t, entries, 1, "only .backup objects directly under the prefix are listed")
	asrt.Equal(name, entries[0].Name)
}

// The full path a real deployment takes: seal, upload, download, unseal.
func TestS3SealedRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	newFakeS3(t)

	dest, err := backup.Open(ctx, "s3://backups/protean")
	require.NoError(t, err)

	key := testKey(t)
	plaintext := []byte("dyn.example.org and every credential behind it")

	sealed, err := backup.Seal(key, plaintext)
	require.NoError(t, err)

	name := backup.Name("protean", "1.0.0", time.Now())
	require.NoError(t, dest.Put(ctx, name, sealed.Bytes))

	downloaded, err := dest.Get(ctx, name)
	require.NoError(t, err)
	asrt.Equal(sealed.Bytes, downloaded)

	opened, err := backup.Unseal(key, downloaded)
	asrt.NoError(err)
	asrt.Equal(plaintext, opened)

	// And what was stored is not the plaintext.
	asrt.NotContains(string(downloaded), "dyn.example.org")
}
