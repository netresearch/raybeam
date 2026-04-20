# Binary-selector stage — pick the pre-built raybeam binary for the target
# platform. release.yml's binaries matrix (build-go-attest.yml) publishes
# raybeam-linux-{386,amd64,arm64,armv6,armv7} as release assets; the
# container job downloads them back into bin/ via gh release download
# before `docker build` runs, and this stage chooses the right one for
# TARGETARCH/TARGETVARIANT instead of compiling Go in Docker.
#
# Local `docker build` outside CI therefore requires the bin/ directory
# to be populated first (e.g. via goreleaser or a manual cross-compile).
FROM alpine:3.23.4 AS binary-selector

ARG TARGETARCH
ARG TARGETVARIANT

COPY bin/raybeam-linux-* /tmp/

RUN set -eux; \
    case "${TARGETARCH}" in \
        arm)              BINARY="raybeam-linux-arm${TARGETVARIANT}" ;; \
        386|amd64|arm64)  BINARY="raybeam-linux-${TARGETARCH}" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cp "/tmp/${BINARY}" /usr/bin/raybeam; \
    chmod +x /usr/bin/raybeam

# Runtime stage
FROM alpine:3.23.4

# OCI image annotations (dynamic labels — created/version/revision — are
# added by docker/metadata-action inside build-container.yml).
LABEL org.opencontainers.image.title="raybeam" \
      org.opencontainers.image.source="https://github.com/netresearch/raybeam" \
      org.opencontainers.image.vendor="Netresearch DTT GmbH" \
      org.opencontainers.image.licenses="MIT"

COPY --from=binary-selector /usr/bin/raybeam /bin/raybeam

# CMD (not ENTRYPOINT) preserves the override semantics the previous
# Dockerfile shipped with — `docker run <image> sh` runs a shell, not
# `raybeam sh`. Users relying on CMD-override behavior keep working.
CMD ["/bin/raybeam"]
