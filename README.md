# Multi-party ECDSA

[![Build Status](https://travis-ci.com/KZen-networks/multi-party-ecdsa.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-ecdsa)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is a Rust implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm).

Threshold ECDSA includes two protocols:

-   Key Generation for creating secret shares.
-   Signing for using the secret shares to generate a signature.

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more.
This library can be used to create MultiSig and ThresholdSig crypto wallet.

## Project Status

-   The library supports **2P-ECDSA** based on Lindell's crypto 2017 paper [1]. Project [Gotham-city](https://github.com/KZen-networks/gotham-city) is a proof of concept for a full two-party Bitcoin wallet that uses this library. See benchmarks and white paper there.

-   The library supports Gennaro and Goldfeder CCS 2018 protocol [2] for **{t,n}-threshold ECDSA**.

-   The library supports **2P-ECDSA** based on Castagnos et. al. crypto 2019 paper [3]. To Enable build with `--features=cclst`.

## Run Demo

The following steps are for setup, key generation with `n` parties and signing with `t+1` parties.

### Setup

1.  We use shared state machine architecture (see [white city](https://github.com/KZen-networks/white-city)). The parameters `parties` and `threshold` can be configured by changing the file: `param`. a keygen will run with `parties` parties and signing will run with any subset of `threshold + 1` parties. `param` file should be located in the same path of the client softwares.

2.  Install [Rust](https://rustup.rs/). Run `cargo build --release --examples` (it will build into `/target/release/examples/`)

3.  Run the shared state machine: `./sm_manager`. Currently configured to be in `127.0.0.1:8001`, this can be changed in `Rocket.toml` file. The `Rocket.toml` file should be in the same folder you run `sm_manager` from.

### KeyGen

run `gg18_keygen_client` as follows: `./gg18_keygen_client http://127.0.0.1:8001 keys.store`. Replace IP and port with the ones configured in setup. Once `n` parties join the application will run till finish. At the end each party will get a local keys file `keys.store` (change filename in command line). This contain secret and public data of the party after keygen. The file therefore should remain private.

### Sign

Run `./gg18_sign_client`. The application should be in the same folder as the `keys.store` file (or custom filename generated in keygen). the application takes three arguments: `IP:port` as in keygen, `filename` and message to be signed: `./gg18_sign_client http://127.0.0.1:8001 keys.store "KZen Networks"`. The same message should be used by all signers. Once `t+1` parties join the protocol will run and will output to screen signatue (R,s).

### Full demo

Run `./run.sh` (located in `/demo` folder) in the same folder as the excutables (usually `/target/release/examples`. Move `params` file to the same folder). It will spawn a shared state machine, clients in the number of parties and signing requests for the `threshold + 1` first parties.

|          !["Multiparty ECDSA Demo"][demo]          |
| :------------------------------------------------: |
| _A 5 parties setup with 3 signers (threshold = 2)_ |

[demo]: https://raw.githubusercontent.com/KZen-networks/multi-party-ecdsa/master/demo/MP-ECDSA%20demo.gif

## Contributions & Development Process

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md), in addition **the [Rust utilities wiki](https://github.com/KZen-networks/rust-utils/wiki) contains information on workflow and environment set-up**.

## License

Multi-party ECDSA is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join the KZen Research [Telegram](https://t.me/kzen_research) for discussions on code and research.

## References

[1] <https://eprint.iacr.org/2017/552.pdf>

[2] <https://eprint.iacr.org/2019/114.pdf>

[3] <https://eprint.iacr.org/2019/503.pdf>
