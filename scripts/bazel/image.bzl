"""Container images for netory's services.

One macro rather than the same ninety lines in three BUILD files. The three
services differ only in their name, their image description and which state
directories they need, so everything else - the platform transitions, the
layer, the two architectures, the index, the local load and the push - is
identical and belongs in one place. A second copy is a second thing to keep in
step.

The shape follows the setup gopskit introduced for its bridge: a static binary
built once per architecture through platform transitions, combined into a
multi-arch index with rules_oci, with a `:load` target that puts the amd64
image into a local Docker engine for testing and a `:push` target the release
workflow runs.

Two differences from that bridge, both forced rather than chosen:

  - These images have a base. All three services make outbound TLS connections,
    and an empty base has no CA bundle - see the comment on the `oci.pull` in
    MODULE.bazel.
  - They declare state directories. protean and signpost keep a Badger
    database and signpost a content tree, and all three open a Unix socket
    under /run. A directory the service expects and the image does not contain
    is a first start that fails on a mount point that is not there.

Build these with `--config=release`, which is what both workflows do. The
binary inside is then the same build as the released executable - optimised and
stripped - rather than a debug build that is most of twice the size. The
configuration is not pinned here on purpose: a macro that forced it would also
force it on a developer building an image to debug something in.
"""

load("@aspect_bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_image_index", "oci_load", "oci_push")
load("@tar.bzl//tar:tar.bzl", "tar")

# Registry the images are published to.
REGISTRY = "ghcr.io/adnoctem"

# The UID and GID every image runs as.
#
# 65532 is the `nonroot` user the distroless base declares, and a fixed
# non-root UID is what lets a pod satisfy the "restricted" Pod Security
# Standard without a securityContext override. It also means a persistent
# volume's ownership can be set once and stay correct across image updates -
# an image that changed its UID would make every existing volume unreadable.
USER_ID = 65532

def _state_entries(directories):
    """Returns mtree lines creating the state directories, parents included."""
    seen = {}
    entries = []

    for directory in directories:
        parts = directory.strip("/").split("/")

        for index in range(len(parts)):
            path = "/".join(parts[:index + 1])
            if path in seen:
                continue

            seen[path] = True

            # Only the leaf belongs to the service. The parents stay
            # root-owned and traversable, exactly as they are on a normal
            # filesystem: a service that owned /var would be a service that
            # could rewrite anything under it.
            if index == len(parts) - 1:
                entries.append(
                    "./{path} uid={uid} gid={uid} mode=0700 time=0 type=dir".format(
                        path = path,
                        uid = USER_ID,
                    ),
                )
            else:
                entries.append(
                    "./{path} uid=0 gid=0 mode=0755 time=0 type=dir".format(path = path),
                )

    return entries

def netory_image(
        service,
        binary,
        description,
        state_dirs = [],
        exposed_ports = [],
        visibility = None):
    """Builds a multi-arch image for one netory service.

    Note the first argument is `service` rather than `name`: this macro
    generates no target named after the service - that name belongs to the
    go_binary - so calling it `name` would be a lie about what it creates.

    Generates, for a service called `service`:

      :image                  the multi-arch index, which is what is published
      :image_linux_amd64      the amd64 image
      :image_linux_arm64      the arm64 image
      :load                   loads the amd64 image as <service>:dev locally
      :tarball                the same image as a docker-format tarball
      :push                   pushes the index; the workflow passes the tags

    Args:
      service: the service name, which is also the image and binary name.
      binary: the go_binary label to put in the image.
      description: the OCI description label.
      state_dirs: absolute directories the service writes to, created in the
        image owned by the service user so a volume has a mount point and a
        bare `docker run` works.
      exposed_ports: ports to declare in the image config. Documentation for
        whoever reads `docker inspect`; it opens nothing by itself.
      visibility: visibility for the generated targets.
    """
    labels = {
        "org.opencontainers.image.description": description,
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.source": "https://github.com/adnoctem/netory",
        "org.opencontainers.image.title": service,
        "org.opencontainers.image.vendor": "Ad Noctem Collective",
    }

    for arch, platform in [("amd64", "linux_amd64"), ("arm64", "linux_arm64")]:
        platform_transition_filegroup(
            name = "binary_linux_" + arch,
            srcs = [binary],
            target_platform = "@io_bazel_rules_go//go/toolchain:" + platform,
        )

        tar(
            name = "layer_linux_" + arch,
            srcs = [":binary_linux_" + arch],
            mtree = [
                # 0555: readable and executable, writable by nobody. The
                # binary in a running container has no business being
                # rewritable, including by the user running it.
                "./{service} uid={uid} gid={uid} mode=0555 time=0 type=file content=$(execpath :binary_linux_{arch})".format(
                    service = service,
                    uid = USER_ID,
                    arch = arch,
                ),
            ] + _state_entries(state_dirs),
        )

    # The architecture-specific base rather than the index, and no `os`,
    # `architecture` or `variant` attributes: rules_oci takes all three from
    # the base and refuses to let an image override them. Pointing each
    # architecture at the matching base repository is how the index below ends
    # up with one correct entry per platform instead of two images claiming to
    # be something they are not.
    oci_image(
        name = "image_linux_amd64",
        base = "@distroless_static_linux_amd64",
        entrypoint = ["/" + service],
        exposed_ports = exposed_ports,
        labels = labels,
        tars = [":layer_linux_amd64"],
        user = "{uid}:{uid}".format(uid = USER_ID),
        workdir = "/",
    )

    oci_image(
        name = "image_linux_arm64",
        base = "@distroless_static_linux_arm64_v8",
        entrypoint = ["/" + service],
        exposed_ports = exposed_ports,
        labels = labels,
        tars = [":layer_linux_arm64"],
        user = "{uid}:{uid}".format(uid = USER_ID),
        workdir = "/",
    )

    oci_image_index(
        name = "image",
        images = [
            ":image_linux_amd64",
            ":image_linux_arm64",
        ],
        visibility = visibility,
    )

    # `bazel run //cmd/<service>:load` puts the amd64 image into the local
    # Docker engine as <service>:dev, which is what a developer runs and what
    # an end-to-end test would import.
    oci_load(
        name = "load",
        image = ":image_linux_amd64",
        repo_tags = [service + ":dev"],
    )

    # The same image as a docker-format tarball, for importing into a cluster
    # without a registry.
    native.filegroup(
        name = "tarball",
        srcs = [":load"],
        output_group = "tarball",
        visibility = visibility,
    )

    # The release workflow passes the tags at run time:
    #   bazel run --stamp //cmd/<service>:push -- --tag 1.2.3 --tag latest
    oci_push(
        name = "push",
        image = ":image",
        repository = "{registry}/{service}".format(registry = REGISTRY, service = service),
    )
