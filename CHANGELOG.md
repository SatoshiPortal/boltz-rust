# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - Unreleased

Must ship as `0.5.0`: this release is source-breaking and must not be
published on the `0.4.x` compatibility line. The version bump itself is left
to the release PR.

### Added
- Multi-output claim and refund transactions. `BtcSwapTx` and `LBtcSwapTx`
  gained a `with_additional_outputs` builder taking `(address, satoshis)`
  pairs; `TransactionOptions::with_additional_outputs` forwards
  `(String, u64)` pairs through `construct_claim` / `construct_refund`. The
  primary output receives the remainder (input - fee - sum of additional
  outputs); additional outputs pay their fixed amounts in the given order.
  Output ordering: Bitcoin keeps the primary at index 0; Liquid claims order
  outputs [primary, additions.., fee] and refunds [fee, primary, additions..].
  Cooperative signing commits to every output.

### Changed
- Bitcoin transaction construction no longer rejects zero-valued outputs:
  construction enforces balance (overflow, overspend) but not dust or relay
  policy, which belongs to the broadcaster.
- Liquid transaction construction now rejects a zero-valued primary output
  up front with a clear protocol error (previously it failed deep inside
  blinding); confidential outputs cannot carry less than 1 satoshi.
- The wrapper conversions of additional-output address strings validate the
  address network on Bitcoin and require confidential addresses on Liquid.
- Fixed `BtcSwapTx::new_claim_with_utxo` silently discarding the result of
  its claim-address network check; an address for the wrong network is now
  rejected.

### Breaking
- `BtcSwapTx` and `LBtcSwapTx` gained a public `additional_outputs` field;
  struct-literal construction of these types must be updated (the
  constructors initialize it to an empty vector).

## [0.4.1]

### Added
- `derivation_path` and `gap_limit` parameters on `post_swap_restore` and
  `post_swap_restore_index`. Pass `derivation_path = Some("m")` when the supplied
  xpub is already the swap-account key (`m/44/0/0/0`) so boltz derives
  `xpub/{index}` directly; omitting the path makes boltz apply its own default
  and match nothing.
- `invoice: Option<String>` field on `SwapRestoreResponse` (boltz returns it for
  submarine and reverse swaps).
- Tests for the swap-restore endpoints.

### Changed
- Boltz `regtest` submodule bumped to latest main.

### Dependencies
- Bumped `elements` from `0.25.0` to `0.26.2`.
- Bumped `lightning-invoice` from `0.32.0` to `0.34.0`.
- Bumped `electrum-client` from `0.21.0` to `0.25.0`.

### Removed
- The automated publish workflow.

### Breaking
- `post_swap_restore` and `post_swap_restore_index` gained `derivation_path` and
  `gap_limit` parameters; existing callers must pass them (`None, None` reproduces
  the previous behaviour).
- `SwapRestoreResponse` gained an `invoice` field; struct-literal construction of
  this type must be updated.

## [0.4.0]

### Added
- BOLT12 invoice support in `submarine_cooperative_claim`. New `LightningInvoice` enum (`Bolt11` / `Bolt12`) in `util::invoice`, plus a `util::bolt12::parse_bolt12_invoice` helper.
- `get_tx(txid)` on the `BitcoinClient` and `LiquidClient` traits, implemented for both Electrum and Esplora backends.
- Optional `transaction: Option<TransactionOut>` field on `ClaimDetails` and `RefundDetails`, plus a new `TransactionOut { id, vout }` struct, to support the extended swap-restore API response.
- Python bindings: `BtcLikeTransaction.hex()` and `BtcLikeTransaction.txid()`.

### Changed
- HTTP error reporting in `BoltzApiClientV2` unified across GET / POST / PATCH. Non-success responses now surface as `Error::HTTPStatusNotSuccess(StatusCode, Value)` carrying both status and the server-returned body (JSON or text), instead of `Error::HTTP(String)` with only the `error` field.
- `201 Created` responses are now treated as success.
- `macros` is published as `boltz-client-macros = "1.0.0"` on crates.io; the workspace no longer depends on it by path.
- Boltz `regtest` submodule bumped; submarine integration tests updated to cooperatively claim mainchain swaps (the new backend defers claims).
- CI now builds the language bindings.
- Removed the "early alpha" warning from the crate docs.

### Dependencies
- Added `lightning = "0.2.2"` (for BOLT12 parsing).
- Bumped `env_logger` from `0.7` to `0.11.8`.
- Locked `wasm-pack` version in tooling.

### Breaking
- `ClaimDetails` and `RefundDetails` gained a new field; struct-literal construction of these types must be updated.
- Boltz HTTP failures previously returned `Error::HTTP(String)`; they now return `Error::HTTPStatusNotSuccess(StatusCode, Value)`. The `Error::HTTP` variant still exists for other call sites, so callers that pattern-matched it for Boltz errors will silently stop matching.

## [0.3.1]

Baseline for this changelog. See git history for prior releases.
