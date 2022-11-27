FROM rust:1 AS builder
WORKDIR app

RUN mkdir src examples; touch src/lib.rs; touch examples/common.rs
COPY Cargo.toml .

RUN cargo build --release

COPY . .

RUN cargo build --release --examples --no-default-features --features curv-kzen/num-bigint

FROM debian:11-slim AS runtime

WORKDIR app

COPY --from=builder /app/target/release/examples/gg20_sm_manager /app/

CMD ["/app/gg20_sm_manager"]
