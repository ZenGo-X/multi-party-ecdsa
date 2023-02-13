#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#!pip3 install ecdsa

from ecdsa import VerifyingKey, SECP256k1
from ecdsa.ellipticcurve import Point
import hashlib
import json

# Importing public key ECPoint
raw_pub = json.load(open("bin/public_key"))

# Build publickey
vk = VerifyingKey.from_string(Point(SECP256k1.curve, int(raw_pub["x"], 16), int(raw_pub["y"], 16), SECP256k1.order).to_bytes(), curve=SECP256k1, hashfunc=hashlib.sha256)

# Importing signed message
message = open("bin/message").read().encode('utf-8')

# Importing signature
raw_sig = json.load(open("bin/signature"))

# Run verify
if vk.verify(b''.join([int(raw_sig["r"], 16).to_bytes(32, byteorder='big'), int(raw_sig["s"], 16).to_bytes(32, byteorder='big')]), message) :
    print("Signature is valid")
else:
    print("Signature is invalid")