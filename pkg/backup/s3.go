package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3Destination stores backups under an S3 prefix.
//
// Credentials come from the AWS credential chain - an instance or task role,
// the shared config, the environment - rather than from anything protean
// stores. That is deliberate: the service already runs somewhere with an
// identity, and copying a long-lived access key into the database to back the
// database up would make the backup configuration itself a secret to protect.
type s3Destination struct {
	client *s3.Client
	bucket string
	prefix string
}

// enforce implementation of the interface
var _ Destination = (*s3Destination)(nil)

// s3ListLimit bounds a listing. A thousand backups is far more history than
// any retention policy keeps, and an unbounded listing on a shared bucket
// could page for a long time.
const s3ListLimit = 1000

// EnvS3Endpoint overrides the S3 endpoint, for MinIO, Ceph and the like.
//
// An environment variable rather than part of the destination string, because
// it is a property of the deployment rather than of the backup location, and
// because the AWS SDK already takes the rest of its configuration that way.
const EnvS3Endpoint = "NETORY_S3_ENDPOINT"

// EnvS3PathStyle forces path-style addressing, which most S3-compatible
// servers need and AWS itself does not.
const EnvS3PathStyle = "NETORY_S3_PATH_STYLE"

// openS3 resolves an `s3://bucket/prefix` destination.
func openS3(ctx context.Context, raw string) (Destination, error) {
	trimmed := strings.TrimPrefix(raw, s3Scheme)

	bucket, prefix, _ := strings.Cut(trimmed, "/")
	bucket = strings.TrimSpace(bucket)

	if bucket == "" {
		return nil, fmt.Errorf("backup: %q has no bucket; write it as %sbucket/prefix", raw, s3Scheme)
	}

	// A trailing slash on the prefix is normalised away and re-added when
	// building keys, so `s3://b/p`, `s3://b/p/` and `s3://b//p/` all mean the
	// same place.
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"backup: could not load AWS configuration: %w. Backups to S3 use the AWS credential "+
				"chain - an instance or task role, the shared config, or the environment", err)
	}

	var options []func(*s3.Options)

	if endpoint := strings.TrimSpace(os.Getenv(EnvS3Endpoint)); endpoint != "" {
		options = append(options, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint) })
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvS3PathStyle)), "true") {
		options = append(options, func(o *s3.Options) { o.UsePathStyle = true })
	}

	return &s3Destination{
		client: s3.NewFromConfig(cfg, options...),
		bucket: bucket,
		prefix: prefix,
	}, nil
}

func (d *s3Destination) Describe() string {
	if d.prefix == "" {
		return s3Scheme + d.bucket
	}

	return s3Scheme + d.bucket + "/" + d.prefix
}

// key builds the object key for a backup name.
func (d *s3Destination) key(name string) string {
	if d.prefix == "" {
		return name
	}

	return d.prefix + "/" + name
}

// Put uploads a backup.
//
// A single PutObject over an in-memory reader, not a multipart upload. The
// reader is seekable and the length is known, which is what the signer wants,
// and MaxBackupBytes already bounds the size well below the 5 GiB single-part
// limit - so the multipart manager would be another dependency earning nothing.
func (d *s3Destination) Put(ctx context.Context, name string, data []byte) error {
	if err := validateName(name); err != nil {
		return err
	}

	_, err := d.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(d.bucket),
		Key:           aws.String(d.key(name)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		ContentType:   aws.String("application/octet-stream"),

		// Server-side encryption as well as protean's own. The backup is
		// already sealed, so this adds nothing cryptographically - but a
		// bucket policy that requires SSE would otherwise reject the upload,
		// and declaring it costs nothing.
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})
	if err != nil {
		return fmt.Errorf("backup: upload to %s: %w", d.Describe(), err)
	}

	return nil
}

// Get downloads a stored backup.
func (d *s3Destination) Get(ctx context.Context, name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.bucket),
		Key:    aws.String(d.key(name)),
	})
	if err != nil {
		var missing *types.NoSuchKey
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("%w: %s in %s", ErrNotFound, name, d.Describe())
		}

		return nil, fmt.Errorf("backup: download %s from %s: %w", name, d.Describe(), err)
	}
	defer func() { _ = out.Body.Close() }()

	if out.ContentLength != nil && *out.ContentLength > MaxBackupBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, name, *out.ContentLength)
	}

	// Read through a bounded reader regardless of the reported length, so a
	// wrong or absent Content-Length cannot make this allocate without limit.
	data, err := readAllBounded(out.Body, MaxBackupBytes)
	if err != nil {
		return nil, fmt.Errorf("backup: read %s from %s: %w", name, d.Describe(), err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmpty, name)
	}

	return data, nil
}

// List returns the stored backups, newest first.
func (d *s3Destination) List(ctx context.Context) ([]Entry, error) {
	listPrefix := d.prefix
	if listPrefix != "" {
		listPrefix += "/"
	}

	out, err := d.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(d.bucket),
		Prefix:  aws.String(listPrefix),
		MaxKeys: aws.Int32(s3ListLimit),
	})
	if err != nil {
		return nil, fmt.Errorf("backup: list %s: %w", d.Describe(), err)
	}

	entries := make([]Entry, 0, len(out.Contents))
	for _, object := range out.Contents {
		if object.Key == nil {
			continue
		}

		// The key relative to the prefix, so a listing shows the same names
		// that Get and the CLI take.
		name := strings.TrimPrefix(*object.Key, listPrefix)
		if validateName(name) != nil || !strings.HasSuffix(name, ".backup") {
			continue
		}

		entry := Entry{Name: name}
		if object.Size != nil {
			entry.Size = *object.Size
		}
		if object.LastModified != nil {
			entry.ModTime = object.LastModified.UTC()
		}

		entries = append(entries, entry)
	}

	sortEntries(entries)

	return entries, nil
}
