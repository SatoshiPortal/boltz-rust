build-debug:
	cargo build
	cp ../target/debug/libboltz_client.so ./python/
	cargo run generate --language python --no-format --library ../target/debug/libboltz_client.so --out-dir python/

build-release:
	cargo build --release
	cargo build  # Also build debug for uniffi to read metadata
	cp ../target/release/libboltz_client.so ./python/
	cargo run generate --language python --no-format --library ../target/debug/libboltz_client.so --out-dir python/

build-python: build-release
	cd python && uv build

prepare-release-python: build-python
	cd python && \
		uvx auditwheel repair dist/*-py3-none-any.whl --wheel-dir dist/ && \
		rm dist/*-py3-none-any.whl && \
		uv run --isolated --no-project --with dist/*.whl python -c "import boltz_client" && \
		uv run --isolated --no-project --with dist/*.tar.gz python -c "import boltz_client"

format-python:
	# Also formats Python tests
	cd python && uv run ruff format . ../tests/bindings

check-python:
	cd python && uv run ruff format --check . ../tests/bindings

test:
	cargo test --package bindings --test test_generated_bindings -- --nocapture
