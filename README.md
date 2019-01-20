[![Build Status](https://travis-ci.com/KZen-networks/multi-party-ecdsa.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-ecdsa)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Multi-party ECDSA
=====================================

This project is a Rust implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm).

Threshold ECDSA includes two protocols:

* Key Generation for creating secret shares.
* Signing for using the secret shares to generate a signature. 

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more. 
This library can be used to create MultiSig and ThresholdSig crypto wallet.

Project Status
-------
* The library supports **2p-ecdsa** based on Lindell's crypto 2017 paper [1]. Project [Gotham-city](https://github.com/KZen-networks/gotham-city) is a proof of concept fora full two-party Bitcoin wallet that uses this library. See benchmarks and white paper there.

* The library supports Gennaro and Goldfeder CCS 2018 protocol [2] for **{t,n}-threshold ECDSA**. 


Contributions & Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md), in addition **the [Rust utilities wiki](https://github.com/KZen-networks/rust-utils/wiki) contains information on workflow and environment set-up**.

License
-------
Multi-party ECDSA is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Contact
-------------------
For any questions, feel free to [email us](mailto:github@kzencorp.com).

References
-------------------

[1] https://eprint.iacr.org/2017/552.pdf

[2] http://stevengoldfeder.com/papers/GG18.pdf
