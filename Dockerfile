# Rust - Nightly : https://github.com/rust-lang/docker-rust-nightly/tree/master/bullseye/slim
FROM debian:bullseye-slim as rust

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libc6-dev \
        wget \
        ; \
    \
    apt-get install -y --no-install-recommends libgmp-dev; \
    \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version; \
    \
    apt-get remove -y --auto-remove \
        wget \
        ; \
    rm -rf /var/lib/apt/lists/*;

# App build
FROM rust as builder
WORKDIR /app
COPY . .
RUN cargo build --release --examples

# App build - slim
FROM debian:bullseye-slim as prod
WORKDIR /app
COPY --from=builder /app/target/release/examples /app
COPY --from=builder /app/Rocket.toml /app
COPY --from=builder /app/params.json /app
