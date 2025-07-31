# Boltz Client Python Bindings

Python bindings for the Boltz Rust library, enabling atomic swaps between Bitcoin, Lightning Network, and Liquid.

## Installation

```bash
pip install boltz_client
```

## Quick Start

> **⚠️ WARNING: All examples are only to be used in REGTEST.**

```python
import boltz_client
import asyncio

async def main():
    # Initialize for regtest (do NOT use this example in production)
    network = boltz_client.Network.REGTEST
    boltz_api = boltz_client.BoltzApiClientV2.default(network)

    # Example: Create a submarine swap (Lightning → Bitcoin)
    key_pair = boltz_client.KeyPair()
    btc_chain = boltz_client.btc_chain_from_network(network)

    invoice = "lightning-invoice-to-pay"

    request = boltz_client.CreateSubmarineRequest(
        _from=btc_chain,
        to=btc_chain,
        invoice=invoice,
        refund_public_key=key_pair.public(),
    )

    swap = await boltz_api.create_swap(request)
    print(f"Send {swap.expected_amount} sats to {swap.address}")

asyncio.run(main())
```

## Swap Types

- **Submarine swaps** - Lightning → On-chain Bitcoin/Liquid
- **Reverse swaps** - On-chain Bitcoin/Liquid → Lightning
- **Chain swaps** - Bitcoin ↔ Liquid atomic swaps

## Examples

Complete working examples are available in the `examples/` directory:

- [`submarine.py`](examples/submarine.py) - Lightning to Bitcoin
- [`reverse.py`](examples/reverse.py) - Bitcoin to Lightning
- [`chain.py`](examples/chain.py) - Bitcoin to Liquid (and vice versa)
