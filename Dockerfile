FROM rust:1.75-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release \
    --bin shdr \
    --bin shadowhare \
    --bin scarb-shdr \
    --bin scarb-shadowhare

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/shdr /usr/local/bin/shdr
COPY --from=builder /build/target/release/shadowhare /usr/local/bin/shadowhare
COPY --from=builder /build/target/release/scarb-shdr /usr/local/bin/scarb-shdr
COPY --from=builder /build/target/release/scarb-shadowhare /usr/local/bin/scarb-shadowhare

ENTRYPOINT ["shdr"]
CMD ["--help"]
