FROM rust:1 AS chef 
RUN cargo install cargo-chef 
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

RUN cargo build --release --examples --no-default-features --features curv-kzen/num-bigint

FROM debian:slim AS runtime

WORKDIR app

COPY --from=builder /app/target/release/examples/gg20_sm_manager /app/

ENTRYPOINT ["/app/gg20_sm_manager"]
