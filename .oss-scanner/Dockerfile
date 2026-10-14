# Security-analysis image: retain source, Rust tools, dependencies and test drivers.
# Build with the repository root as context:
#   docker build -f .oss-scanner/Dockerfile -t membrane-oss-scanner .
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang cmake pkg-config libssl-dev \
      git python3 gdb \
    && rm -rf /var/lib/apt/lists/*

# OSS Scanner expects the complete checkout at /src.
COPY . /src
WORKDIR /src

# Download every locked dependency while the image build still has network access.
# Keep the Cargo registry and toolchain in the final image for offline patch testing.
RUN cargo fetch --locked
ENV CARGO_NET_OFFLINE=true
ENV RUSTFLAGS="-C force-frame-pointers=yes -C debuginfo=2"

# --frozen proves these commands need neither network nor lockfile changes.
# Build all crates, binaries, examples and test drivers, including optional features.
RUN cargo build --workspace --all-targets --all-features --frozen
RUN cargo test --workspace --frozen \
    && cargo test --workspace --all-features --frozen \
    && cargo check -p membrane-cli --no-default-features --features ots --frozen \
    && cargo check -p membrane-cli --no-default-features --features demo --frozen

CMD ["bash"]
