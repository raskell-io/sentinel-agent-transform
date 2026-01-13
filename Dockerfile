# syntax=docker/dockerfile:1.4

# Sentinel Transform Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-transform /sentinel-agent-transform

LABEL org.opencontainers.image.title="Sentinel Transform Agent" \
      org.opencontainers.image.description="Sentinel Transform Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-transform"

ENV RUST_LOG=info,sentinel_agent_transform=debug \
    SOCKET_PATH=/var/run/sentinel/transform.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-transform"]
