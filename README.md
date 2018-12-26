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
* The library supports **2p-ecdsa** based on Lindell's crypto 2017 paper [1]. This implementation is being used as part of KMS-secp256k1 repo (https://github.com/KZen-networks/kms-secp256k1) for distributed key management. 

* The library supports Gennaro and Goldfeder ccs 2018 protocol [2] for **{t,n}-threshold ECDSA**. The updated code can be found in a different branch: https://github.com/KZen-networks/multi-party-ecdsa/tree/pdl-sub-protocol/src/protocols/multi_party_ecdsa/gg_2018 and it is not yet benchmarked.  

* Note - the code is not fully audited yet.

Performance
-------
for two party key generation: 
* _Provider:_ EC2 AWS, _bench_: self::bench_full_keygen_party_one_two.

| Feature    | Model     | vCPU | Mem (GiB) | SSD Storage (GB) | Dedicated EBS Bandwidth (Mbps) | Bench                                   |
|------------|-----------|------|-----------|------------------|--------------------------------|-----------------------------------------|
| **Keygen** | m4.xlarge | 4    | 16        | 28               | 750                            | 1,528,965,676 ns/iter (+/- 195,059,290) |


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
