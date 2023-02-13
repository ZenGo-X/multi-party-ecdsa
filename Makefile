target: all
all:
	@ cargo +nightly build --release --examples

.PHONY: run keygen presign sign compile 
run: 
	@ ./demo/run21.sh
keygen: reset startSM
	@ ./demo/bs21/keygen.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi
presign: startSM
	@ ./demo/bs21/presign.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi
sign:
	@ ./demo/bs21/sign.sh
compile: startSM
	@ ./demo/bs21/compile_sig.sh
	@ sleep 10
	@ if pgrep sm_manager; then pkill sm_manager; fi

.PHONY: run20 keygen20 presign20 sign20 compile20 
run20: 
	@ ./demo/run20.sh
keygen20: reset startSM
	@ ./demo/gg20/keygen.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi
presign20: startSM
	@ ./demo/gg20/presign.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi
sign20: startSM
	@ ./demo/gg20/sign.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi
compile20: startSM
	@ ./demo/gg20/compile_sig.sh
	@ sleep 7
	@ if pgrep sm_manager; then pkill sm_manager; fi

.PHONY: clean reset startSM stopSM
startSM:
	@ ./target/release/examples/sm_manager &
stopSM:
	@ if pgrep sm_manager; then pkill sm_manager; fi

clean: reset
	@ cargo clean --release
reset: 
	@ rm -f *.store bin/*.store bin/*/*.store
	@ rm -f signature bin/*/signature bin/*/public_key
	@ if pgrep sm_manager; then pkill sm_manager; fi
