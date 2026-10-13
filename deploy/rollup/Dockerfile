FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY membrane-core membrane-core
COPY membrane-gate membrane-gate
COPY membrane-cli membrane-cli
COPY membrane-dashboard membrane-dashboard
COPY membrane-advisor membrane-advisor
RUN cargo build --locked --release -p membrane-cli --no-default-features --features ots

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/membrane /usr/local/bin/membrane
ENTRYPOINT ["/usr/local/bin/membrane"]
