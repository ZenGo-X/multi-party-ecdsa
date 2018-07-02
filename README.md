[![Build Status](https://travis-ci.com/KZen-networks/multi-party-ecdsa.svg?branch=master)](https://travis-ci.com/KZen-networks/multi-party-ecdsa)

KZen Multi-party ECDSA
=====================================

This project is a Rust implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm).

Threshold ECDSA includes two protocols:

* Key Generation for creating secret shares.
* Signing for using the secret shares to generate a signature. 

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more.
This library can be used to create MultiSig and ThresholdSig crypto wallet.

License
-------
Multi-party ECDSA is released under the terms of the GPL-3.0 license. See [LICENCE](LICENCE) for more information.


Development Process
-------------------
The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).
