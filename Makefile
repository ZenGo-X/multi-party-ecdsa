all:
	ln -fs target/debug/libmulti_party_ecdsa.so .
	cargo build
	cbindgen . -o libmulti_party_ecdsa.h -l c
	python3 mpecdsa_build.py

clean:
	rm -vi *.o *.so *.h *.c
