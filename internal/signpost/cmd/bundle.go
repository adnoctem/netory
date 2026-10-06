package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/internal/signpost/server"
	"github.com/adnoctem/netory/pkg/admin"
)

// newBundleCommand builds `signpost bundle`.
func newBundleCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Publish, inspect and withdraw releases",
		Long: "A bundle is one .zip or .tar.gz containing scripts and exactly one manifest.\n\n" +
			"Publishing creates an immutable release and moves an alias to it. Rollback moves the\n" +
			"alias back. A release is never modified, so the bytes served under a release are the\n" +
			"bytes that were published under it.",
	}

	cmd.AddCommand(
		newBundlePublishCommand(opts),
		newBundleValidateCommand(opts),
		newBundleListCommand(opts),
		newBundleRollbackCommand(opts),
		newBundleRemoveCommand(opts),
	)

	return cmd
}

// newBundlePublishCommand builds `signpost bundle publish`.
func newBundlePublishCommand(opts *Options) *cobra.Command {
	var (
		signature string
		publicKey string
		aliases   []string
		noAlias   bool
	)

	cmd := &cobra.Command{
		Use:   "publish <bundle.tar.gz|bundle.zip>",
		Short: "Publish a bundle as a new release",
		Long: "Validates a bundle and publishes it, then moves the serving alias to the new release.\n\n" +
			"The server validates the bundle again on its own: the local pass is for fast feedback,\n" +
			"and the server's is the one that is trusted, since the CLI runs outside the server's\n" +
			"control.\n\n" +
			"The release identifier in the manifest must not already exist. A release is immutable,\n" +
			"so republishing under the same name is refused rather than silently replacing bytes\n" +
			"that clients may already have checksummed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive, err := readBundleFile(args[0])
			if err != nil {
				return err
			}

			fields := map[string]string{}

			if len(aliases) > 0 {
				fields[server.FieldAliases] = strings.Join(aliases, ",")
			}

			if publicKey != "" {
				fields[server.FieldPublicKey] = publicKey
			}

			if noAlias {
				fields[server.FieldNoAlias] = "true"
			}

			uploads := []admin.Upload{{
				Field:    server.FieldArchive,
				Filename: filepath.Base(args[0]),
				Content:  archive,
			}}

			if signature != "" {
				signed, err := os.ReadFile(signature)
				if err != nil {
					return fmt.Errorf("read the signature %q: %w", signature, err)
				}

				uploads = append(uploads, admin.Upload{
					Field:    server.FieldSignature,
					Filename: filepath.Base(signature),
					Content:  signed,
				})
			}

			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.PublishResponse
			if err := client.PostMultipart(cmd.Context(), server.APIPrefix+"/bundles",
				fields, uploads, &result); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, result)
			}

			fmt.Fprintf(out, "published %s\n", result.Release.Release)
			fmt.Fprintf(out, "  archive:   %s (%s)\n",
				result.Release.ArchiveSHA256, humanBytes(result.Release.ArchiveSize))
			fmt.Fprintf(out, "  signature: %s\n", result.Release.Signature)

			if len(result.Release.TruncationSkipped) > 0 {
				// Surfaced right after a successful publish, not buried: a
				// route that opted out of the §6.3 check is the one route
				// whose partial delivery could execute.
				fmt.Fprintf(out, "  warning:   truncation check skipped for %s\n",
					strings.Join(result.Release.TruncationSkipped, ", "))
			}

			if len(result.Moved) > 0 {
				names := make([]string, 0, len(result.Moved))
				for _, alias := range result.Moved {
					names = append(names, alias.Name)
				}

				fmt.Fprintf(out, "  aliases:   %s\n", strings.Join(names, ", "))
			} else {
				fmt.Fprintln(out,
					"  aliases:   none moved; reachable on its versioned paths only")
			}

			fmt.Fprintln(out, "\nroutes")

			t := newTable(out, "  path", "checksum", "versioned", "type", "size")
			for _, route := range result.Release.Routes {
				t.row("  "+route.Path, route.ChecksumPath, route.VersionedPath,
					route.ContentType, humanBytes(route.Size))
			}

			return t.flush()
		},
	}

	cmd.Flags().StringVar(&signature, "signature", "",
		"detached minisign signature for the bundle (a .minisig file)")
	cmd.Flags().StringVar(&publicKey, "public-key", "",
		"verify against this minisign public key instead of the configured one")
	cmd.Flags().StringSliceVar(&aliases, "alias", nil,
		"alias to move to the new release; repeatable, defaults to the serving alias")
	cmd.Flags().BoolVar(&noAlias, "no-alias", false,
		"publish without moving any alias, for staging a release before it goes live")

	return cmd
}

// newBundleValidateCommand builds `signpost bundle validate`.
//
// Local by default, because this is the command an author runs while writing a
// bundle and it has to work with no server anywhere near. --server adds the
// checks only the server can make: whether the release name is taken, and
// whether the signature verifies against the key that instance trusts.
func newBundleValidateCommand(opts *Options) *cobra.Command {
	var (
		useServer bool
		signature string
		publicKey string
	)

	cmd := &cobra.Command{
		Use:   "validate <bundle.tar.gz|bundle.zip>",
		Short: "Validate a bundle without publishing it",
		Long: "Runs the full validation locally: archive limits, manifest schema, route resolution,\n" +
			"reserved paths, and the truncation-protection check of every script.\n\n" +
			"Works without a running server. Pass --server to validate against one as well, which\n" +
			"additionally reports whether the release name is already taken and verifies the\n" +
			"signature against the key that instance trusts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive, err := readBundleFile(args[0])
			if err != nil {
				return err
			}

			if useServer {
				return validateOnServer(cmd, opts, args[0], archive, signature, publicKey)
			}

			return validateLocally(cmd, opts, archive, signature, publicKey)
		},
	}

	cmd.Flags().BoolVar(&useServer, "server", false,
		"also validate against the running server")
	cmd.Flags().StringVar(&signature, "signature", "",
		"detached minisign signature to verify (a .minisig file)")
	cmd.Flags().StringVar(&publicKey, "public-key", "",
		"minisign public key to verify the signature against")

	return cmd
}

// validateLocally runs the §4.2 validation in this process.
func validateLocally(
	cmd *cobra.Command,
	opts *Options,
	archive []byte,
	signature, publicKey string,
) error {
	opened, err := bundle.Open(archive)
	if err != nil {
		return err
	}

	report := server.ValidateResponse{
		Release:       opened.Manifest.Release,
		Description:   opened.Manifest.Description,
		ArchiveSize:   opened.Size,
		ArchiveSHA256: opened.SHA256,
		ManifestName:  opened.ManifestName,
		Signature:     "unsigned",
	}

	for i := range opened.Manifest.Routes {
		route := &opened.Manifest.Routes[i]
		file := opened.Files[route.File]

		if route.SkipTruncationCheck {
			report.Skipped = append(report.Skipped, route.Path)
		} else if err := bundle.CheckTruncation(route.File, route.Path, file.Content); err != nil {
			return err
		}

		report.Routes = append(report.Routes, server.RouteResponse{
			Path:          route.Path,
			File:          route.File,
			ContentType:   route.ContentTypeFor(),
			SHA256:        file.SHA256,
			Size:          int64(len(file.Content)),
			ChecksumPath:  route.ChecksumPath(),
			VersionedPath: app.VersionedPath(opened.Manifest.Release, route.Path),
		})
	}

	if signature != "" {
		if publicKey == "" {
			return errors.New(
				"a signature was given with no --public-key to verify it against: " +
					"a signature nobody checks is not a signature")
		}

		signed, err := os.ReadFile(signature)
		if err != nil {
			return fmt.Errorf("read the signature %q: %w", signature, err)
		}

		parsed, err := bundle.VerifyBundle(publicKey, signed, archive)
		if err != nil {
			return err
		}

		key, err := bundle.ParsePublicKey(publicKey)
		if err != nil {
			return err
		}

		report.Signature = "verified"
		report.SignatureKey = key.KeyIDHex()
		_ = parsed
	}

	return printValidation(cmd, opts, report, true)
}

// validateOnServer sends the bundle to the running server for validation.
func validateOnServer(
	cmd *cobra.Command,
	opts *Options,
	path string,
	archive []byte,
	signature, publicKey string,
) error {
	uploads := []admin.Upload{{
		Field:    server.FieldArchive,
		Filename: filepath.Base(path),
		Content:  archive,
	}}

	if signature != "" {
		signed, err := os.ReadFile(signature)
		if err != nil {
			return fmt.Errorf("read the signature %q: %w", signature, err)
		}

		uploads = append(uploads, admin.Upload{
			Field:    server.FieldSignature,
			Filename: filepath.Base(signature),
			Content:  signed,
		})
	}

	fields := map[string]string{}
	if publicKey != "" {
		fields[server.FieldPublicKey] = publicKey
	}

	client, err := opts.client()
	if err != nil {
		return err
	}

	var report server.ValidateResponse
	if err := client.PostMultipart(cmd.Context(), server.APIPrefix+"/bundles/validate",
		fields, uploads, &report); err != nil {
		return err
	}

	return printValidation(cmd, opts, report, false)
}

// printValidation renders a validation report.
func printValidation(
	cmd *cobra.Command,
	opts *Options,
	report server.ValidateResponse,
	local bool,
) error {
	out := cmd.OutOrStdout()
	if opts.JSON {
		return printJSON(out, report)
	}

	where := "the running server"
	if local {
		where = "this binary"
	}

	fmt.Fprintf(out, "%s is valid, as checked by %s\n", report.Release, where)
	fmt.Fprintf(out, "  manifest:  %s\n", report.ManifestName)
	fmt.Fprintf(out, "  archive:   %s (%s)\n", report.ArchiveSHA256, humanBytes(report.ArchiveSize))
	fmt.Fprintf(out, "  signature: %s", report.Signature)

	if report.SignatureKey != "" {
		fmt.Fprintf(out, " (%s)", report.SignatureKey)
	}

	fmt.Fprintln(out)

	if report.Exists {
		fmt.Fprintf(out,
			"  warning:   release %s is already published, so publishing it would be refused\n",
			report.Release)
	}

	if len(report.Skipped) > 0 {
		fmt.Fprintf(out, "  warning:   truncation check skipped for %s\n",
			strings.Join(report.Skipped, ", "))
	}

	if local {
		fmt.Fprintln(out,
			"\nnote: the server validates again on publish, and its pass is the one that counts")
	}

	fmt.Fprintln(out, "\nroutes")

	t := newTable(out, "  path", "file", "type", "size")
	for _, route := range report.Routes {
		t.row("  "+route.Path, route.File, route.ContentType, humanBytes(route.Size))
	}

	return t.flush()
}

// newBundleListCommand builds `signpost bundle list`.
func newBundleListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the published releases",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var releases []server.ReleaseResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/bundles", &releases); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, releases)
			}

			if len(releases) == 0 {
				fmt.Fprintln(out, "no releases published")

				return nil
			}

			t := newTable(out, "release", "routes", "aliases", "signature", "published", "by")
			for _, release := range releases {
				name := release.Release
				if release.Serving {
					// A marker rather than a column: which release is live is
					// the first thing an operator looks for, and it should be
					// visible without reading across the row.
					name = "* " + name
				}

				t.row(
					name,
					strconv.Itoa(len(release.Routes)),
					dash(strings.Join(release.Aliases, ",")),
					release.Signature,
					release.PublishedAt.Format("2006-01-02 15:04"),
					release.PublishedBy,
				)
			}

			if err := t.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\n* is the release the public listener is serving")

			return nil
		},
	}
}

// newBundleRollbackCommand builds `signpost bundle rollback`.
func newBundleRollbackCommand(opts *Options) *cobra.Command {
	var alias string

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Move an alias back to the release it pointed at before",
		Long: "Moves an alias back one step, which is how a bad publish is undone.\n\n" +
			"signpost keeps one step of history per alias. A second rollback returns to the release\n" +
			"the first one left, so rollback is its own undo.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var moved server.AliasResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/bundles/rollback",
				server.RollbackRequest{Alias: alias}, &moved)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, moved)
			}

			fmt.Fprintf(out, "%s now points at %s\n", moved.Name, moved.Release)

			if moved.Previous != "" {
				fmt.Fprintf(out, "  a further rollback would return it to %s\n", moved.Previous)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&alias, "alias", "",
		"which alias to roll back; defaults to the serving alias")

	return cmd
}

// newBundleRemoveCommand builds `signpost bundle remove`.
func newBundleRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "remove <release>",
		Short:   "Delete a release no alias points at",
		Aliases: []string{"rm"},
		Long: "Deletes a release and its stored content.\n\n" +
			"Refused while any alias points at it, because the routes that alias serves would\n" +
			"otherwise resolve to nothing. Note that §8.1 expects releases to be retained so any\n" +
			"script ever served can be reproduced for an audit - removing one is a deliberate\n" +
			"departure from that, not routine housekeeping.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/bundles/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])

			return nil
		},
	}
}

// readBundleFile reads a bundle from disk, refusing one too large to publish.
//
// Checked here as well as in the server so an operator who points the command
// at the wrong file is told immediately, rather than after uploading it.
func readBundleFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read the bundle %q: %w", path, err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("%q is a directory: signpost publishes a .zip or .tar.gz archive", path)
	}

	if info.Size() > bundle.MaxArchiveBytes {
		return nil, fmt.Errorf("the bundle is %s, the limit is %s",
			humanBytes(info.Size()), humanBytes(bundle.MaxArchiveBytes))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the bundle %q: %w", path, err)
	}

	return content, nil
}
