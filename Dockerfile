FROM rust:latest

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release --examples --no-default-features --features curv-kzen/num-bigint

CMD [ "./target/release/examples/gg20_sm_manager" ]