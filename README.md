# Multi-party ECDSA

[![Build Status](https://travis-ci.com/KZen-networks/multi-party-ecdsa.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-ecdsa)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This project is a Rust implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm).

Threshold ECDSA includes two protocols:

-   Key Generation for creating secret shares.
-   Signing for using the secret shares to generate a signature.

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more.
This library can be used to create MultiSig and ThresholdSig crypto wallet. For a full background on threshold signatures please read our Binance academy article [Threshold Signatures Explained](https://www.binance.vision/security/threshold-signatures-explained).

## Library Introduction
The library was built with four core design principles in mind: 
1. Multi-protocol support
2. Built for cryptography engineers
3. Foolproof
4. Black box use of cryptographic primitives

To learn about the core principles as well as on the [audit](https://github.com/KZen-networks/multi-party-ecdsa/tree/master/audits) process and security of the library, please read our [Intro to multiparty ecdsa library](https://zengo.com/introducing-multi-party-ecdsa-library/) blog post.

## Use It


The library implements three different protocols for threshold ECDSA. The protocols presents differnt tradeoffs in terms of parameters, security assumptions and efficiency. 

|  Protocol                                               | High Level code                                                             |
| -------------------------------------------- | -------------------------------------------- |
|  Lindell 17 [1]  |  [Gotham-city](https://github.com/KZen-networks/gotham-city) (accepted to [CIW19](https://ifca.ai/fc19/ciw/program.html)) is a two party bitcoin wallet, including benchmarks. [KMS](https://github.com/KZen-networks/kms-secp256k1) is a Rust wrapper library that implements a general purpose two party key management system. [thresh-sig-js](https://github.com/KZen-networks/thresh-sig-js) is a Javascript SDK | 
| Gennaro, Goldfeder 19 [2] ([video](https://www.youtube.com/watch?v=PdfDZIwuZm0)) | [tss-ecdsa-cli](https://github.com/cryptochill/tss-ecdsa-cli) is a wrapper CLI for full threshold access structure, including network and threshold HD keys ([BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)). See [Demo](https://github.com/KZen-networks/multi-party-ecdsa#run-demo) in this library to get better low level understanding| 
|Castagnos et. al. 19 [3]| WIP, Currently enabled as a feature in this library. To Enable build with `--features=cclst`.|

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

Run `./run.sh` (located in `/demo` folder) in the main folder. Move `params` file to the same folder as the excutables (usually `/target/release/examples`). The script will spawn a shared state machine, clients in the number of parties and signing requests for the `threshold + 1` first parties.

`sm_manager` rocket server runs in _production_ mode by default. You may modify the `./run.sh` to config it to run in different environments. For example, to run rocket server in _development_:

```
ROCKET_ENV=development ./target/release/examples/sm_manager
```

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
