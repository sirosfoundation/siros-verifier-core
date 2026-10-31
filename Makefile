.PHONY: build test fmt clippy check mutation kotlin-test audit fuzz

build:
	cargo build --workspace

test:
	cargo test --workspace --all-features

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

check: fmt clippy test

mutation:
	python3 scripts/mutate.py

kotlin-test:
	ffi/scripts/kotlin-test.sh

audit:
	scripts/audit.sh

fuzz:
	scripts/fuzz-smoke.sh
