# Binary-selector stage — pick the pre-built raybeam binary for the target
# platform. build-go-attest.yml (from release.yml's binaries matrix) produces
# bin/raybeam-linux-{386,amd64,arm64,armv6,armv7}; this stage chooses the
# right one for TARGETARCH/TARGETVARIANT instead of compiling Go in Docker.
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

ENTRYPOINT ["/bin/raybeam"]
