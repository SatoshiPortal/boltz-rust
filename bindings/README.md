# Bindings

Uniffi bindings for the Boltz Rust library.

[UniFFI](https://mozilla.github.io/uniffi-rs/) enables automatic generation of bindings for multiple programming languages from a single Rust codebase. Currently, only Python bindings are implemented in this repository, but UniFFI supports many other languages including Kotlin, Swift, Ruby, and more.

## Python

### Installation

#### From PyPI

```bash
pip install boltz_client
```

#### From Source

1. **Prerequisites**

   - Rust toolchain (1.70+)
   - Python 3.10+
   - `uv` package manager

2. **Build the bindings**

   ```bash
   cd bindings
   make build-python
   ```

3. **Install the wheel**
   ```bash
   cd python/dist
   pip install boltz_client-*.whl
   ```

## Development

### Building from Source

The Makefile provides several build targets:

```bash
# Build debug version with Python bindings
make build-debug

# Build release version with Python bindings
make build-release

# Build Python package (wheel)
make build-python
```

### Generated Files

The build process generates:

- `libboltz_client.so` - The compiled Rust library
- `boltz_client.py` - Python bindings module
- `dist/boltz_client-*.whl` - Installable Python wheel

### Testing

Tests can be run from the root of the repository with `make test` in the [regtest environment](README.md#testing).
