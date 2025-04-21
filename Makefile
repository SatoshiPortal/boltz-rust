UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
	CLANG_PREFIX += AR=$(shell brew --prefix llvm)/bin/llvm-ar CC=$(shell brew --prefix llvm)/bin/clang
endif

LND_MACAROON_HEX=$(shell xxd -p regtest/boltz/data/lnd1/data/chain/bitcoin/regtest/admin.macaroon | tr -d '\n')
BITCOIND_COOKIE=$(shell cat regtest/boltz/data/bitcoind/regtest/.cookie)
REGTEST_PREFIX = LND_MACAROON_HEX=$(LND_MACAROON_HEX) BITCOIND_COOKIE=$(BITCOIND_COOKIE)

init:
	cargo install wasm-pack

build: cargo-build cargo-clippy

cargo-build:
	cargo build --all-targets --all-features

wasm-build:
	cargo build --target=wasm32-unknown-unknown --all-features

clippy: cargo-clippy wasm-clippy

test: cargo-test wasm-test

regtest-test: cargo-regtest-test wasm-regtest-test

cargo-clippy:
	cargo clippy --all-targets --all-features -- -D warnings

cargo-test:
	cargo test --features "esplora, electrum, lnurl, ws"  -- --nocapture

cargo-regtest-test:
	$(REGTEST_PREFIX) cargo test --features "electrum, regtest, ws" -- --nocapture

wasm-clippy:
	$(CLANG_PREFIX) cargo clippy --target=wasm32-unknown-unknown --all-features -- -D warnings

BROWSER ?= firefox

wasm-test:
	$(CLANG_PREFIX) wasm-pack test --headless --$(BROWSER)

wasm-test-chrome:
	BROWSER=chrome $(MAKE) wasm-test

wasm-test-safari:
	BROWSER=safari $(MAKE) wasm-test

wasm-regtest-test:
	$(CLANG_PREFIX) $(REGTEST_PREFIX) WASM_BINDGEN_TEST_TIMEOUT=500 wasm-pack test --headless --$(BROWSER) --features regtest,ws -- regtest

wasm-regtest-test-chrome:
	BROWSER=chrome $(MAKE) wasm-regtest-test

wasm-regtest-test-safari:
	BROWSER=safari $(MAKE) wasm-regtest-test
