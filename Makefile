all:
	cargo build
	cbindgen . -o libmulti_party_ecdsa.h -l c
	python3 mpecdsa_build.py
