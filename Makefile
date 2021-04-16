lint:
	cargo clippy -- -D warnings
	cargo fmt --all -- --check
