# SPDX-License-Identifier: MIT OR Apache-2.0
#
# IronBus distroless container image (#104, parent #17).
#
# The runtime stage is `gcr.io/distroless/static`, which provides exactly what a static musl binary
# needs and nothing else: CA certificates (for a future TLS uplink, #107), tzdata, /etc/passwd with a
# `nonroot` user, and NO shell, package manager, or libc. We run as the non-root `nonroot` user.
#
# A `FROM scratch` variant is RESERVED, not used: scratch carries no CA certs, no tzdata, and no
# passwd entry, so a binary that does TLS or non-root execution would silently break on it. We
# default to distroless to avoid that footgun (see docs/DISTRIBUTION.md); scratch is only viable once
# there is provably no TLS or tz dependency.
#
# REQUIRED WRITABLE VOLUME: the broker's WAL/segment directory (IRONBUS_DATA_DIR, default
# /var/lib/ironbus) MUST be a writable volume mount owned by the nonroot uid (65532). The image
# itself is read-only; without the mount the broker cannot open its data dir. Example:
#
#   docker run --rm \
#     -v ironbus-data:/var/lib/ironbus \
#     -e IRONBUS_ADDR=0.0.0.0:7777 -p 7777:7777 \
#     ghcr.io/elares/ironbus:latest
#
# Build (multi-stage, produces the SAME static musl binary the release ships):
#   docker build -t ironbus:dev .
#
# Or build from a release artifact without recompiling (CI path; see .github/workflows/release.yml):
#   docker build --build-arg IRONBUS_BIN=dist/ironbus-linux-amd64 \
#     -f Dockerfile.release .

ARG RUST_VERSION=1.78
ARG TARGET=x86_64-unknown-linux-musl

# ---- build stage: the static musl binary -------------------------------------------------------
FROM rust:${RUST_VERSION}-slim AS build
ARG TARGET
WORKDIR /src
RUN rustup target add "${TARGET}"
COPY . .
# --locked uses the committed Cargo.lock; the release profile (size-optimized, panic=abort, stripped)
# comes from the workspace Cargo.toml. The musl target is fully static (no PT_INTERP, no NEEDED libs).
RUN cargo build --release --locked -p ironbus-cli --target "${TARGET}" \
    && cp "target/${TARGET}/release/ironbus" /ironbus

# ---- runtime stage: distroless static, non-root ------------------------------------------------
FROM gcr.io/distroless/static:nonroot AS runtime
LABEL org.opencontainers.image.source="https://github.com/ELares/IronBus" \
      org.opencontainers.image.description="IronBus durable edge message queue (distroless static)" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=build /ironbus /usr/local/bin/ironbus

# The WAL/segment dir: a required writable VOLUME, owned by the nonroot uid 65532 at mount time.
ENV IRONBUS_DATA_DIR=/var/lib/ironbus \
    IRONBUS_ADDR=0.0.0.0:7777
VOLUME ["/var/lib/ironbus"]
EXPOSE 7777

# Run as the distroless `nonroot` user (uid 65532), never root.
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ironbus"]
CMD ["serve"]
