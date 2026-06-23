REPO_ROOT := $(abspath ..)
CARGO_TARGET_DIR ?= ../target
MANYLINUX_IMAGE ?= quay.io/pypa/manylinux_2_28_x86_64
DOCKER_PLATFORM_ARG := $(if $(MANYLINUX_PLATFORM),--platform $(MANYLINUX_PLATFORM),)

build-debug:
	cargo build
	cp $(CARGO_TARGET_DIR)/debug/libboltz_client.so ./python/
	cargo run generate --language python --no-format --library $(CARGO_TARGET_DIR)/debug/libboltz_client.so --out-dir python/

build-release:
	cargo build --release
	cargo build  # Also build debug for uniffi to read metadata
	cp $(CARGO_TARGET_DIR)/release/libboltz_client.so ./python/
	cargo run generate --language python --no-format --library $(CARGO_TARGET_DIR)/debug/libboltz_client.so --out-dir python/

build-python: build-release
	cd python && uv build

build-python-manylinux:
	docker run --rm $(DOCKER_PLATFORM_ARG) \
		-v "$(REPO_ROOT):/io" \
		-w /io/bindings \
		"$(MANYLINUX_IMAGE)" \
		bash scripts/build-python-manylinux.sh

format-python:
	# Also formats Python tests
	cd python && uv run ruff format . ../tests/bindings

check-python:
	cd python && uv run ruff format --check . ../tests/bindings

test:
	cargo test --package bindings --test test_generated_bindings -- --nocapture
