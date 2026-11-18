# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `BtcSwapTx::new_claim_confirmed` builds a claim from a confirmed lockup
  only, so Boltz cannot double-spend its lockup after the claim reveals the
  preimage. It fails, for the caller to retry, until the chain client sees
  the lockup confirmed. Backed by the new
  `BitcoinClient::get_confirmed_address_utxos`.
- `CreateReverseResponse::validate_magic_routing_hint` checks that the
  invoice carries the magic routing hint with our claim key, as the Boltz
  docs require of a receiver that sent an address signature. Without it,
  Boltz could put its own key in the hint and a payer would pay Boltz's
  address directly.
- Timeout bounds against the current tip:
  `CreateSubmarineResponse::validate_timeout`,
  `CreateReverseResponse::validate_timeout` and
  `CreateChainResponse::validate_timeouts`. A lockup Boltz funds must leave
  at least six hours to claim; a lockup the user funds must be refundable
  within fourteen days and not already. Backed by the new
  `BitcoinClient::get_tip_height` and `LiquidClient::get_tip_height`.
- The new client methods have default bodies that return an error, so
  existing client implementations keep compiling.

### Fixed
- Claims no longer take their lockup UTXO from the Boltz API. `new_claim`
  on Bitcoin and Liquid used Boltz's copy of the lockup transaction when the
  chain client errored (and, on Liquid, when it saw no UTXO), checked only
  against Boltz's own txid; a cooperative claim then revealed the preimage
  for a lockup that may never have existed. A claim now fails, for the
  caller to retry, until its own chain client sees the lockup. Refunds keep
  the fallback: refunding our own lockup reveals no secret.
- Refunds no longer trust the Boltz API's copy of the lockup transaction.
  When the chain client errored (and, on Liquid, saw no UTXO), `new_refund`
  built the refund from the lockup transaction Boltz served. That
  transaction is now accepted only once the chain client returns it by
  txid, and the refunded output is read from the chain client's copy;
  otherwise the refund fails for the caller to retry.

## [0.5.0] - 2026-11-17

Must ship as `0.5.0`: this release is source-breaking and must not be
published on the `0.4.x` compatibility line.

### Added
- Boltz-free claim and refund constructors. `BtcSwapTx::new_claim_with_utxo`
  and `LBtcSwapTx::new_claim_with_utxo` are now public, and
  `BtcSwapTx::new_refund_with_utxo` / `LBtcSwapTx::new_refund_with_utxo` are
  new. They build the transaction from a caller-provided lockup UTXO with no
  `BoltzApiClientV2` in scope, so a script-path claim or refund can run
  without any Boltz API call; fetch the UTXO with
  `BtcSwapScript::fetch_utxos` / `LBtcSwapScript::fetch_utxo`.
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
- Bitcoin transaction construction enforces balance (overflow, overspend)
  and rejects any output — the computed primary remainder included — below
  the dust threshold for its script type: an unrelayable swap transaction
  cannot confirm before the swap timeout, and for cooperative claims the
  preimage has already been shared by broadcast time.
- Liquid transaction construction now rejects a zero-valued primary output
  up front with a clear protocol error (previously it failed deep inside
  blinding); confidential outputs cannot carry less than 1 satoshi.
- The wrapper conversions of additional-output address strings validate the
  address network on Bitcoin and require confidential addresses on Liquid.
- Fixed `BtcSwapTx::new_claim_with_utxo` silently discarding the result of
  its claim-address network check; an address for the wrong network is now
  rejected.
- MuSig nonce generation and key conversions adapted to the `secp256k1`
  0.33 API, and the code to the `elements` 0.27 API; no behaviour change.
- Native, lint, test and WASM CI jobs are pinned to Rust 1.100.0, and the
  library and tests pass its strict Clippy.

### Dependencies
- Replaced the yanked `secp256k1` `0.32.0-beta.0` (MuSig) with `0.33.1`.
- Bumped `elements` from `0.26.2` to `0.27.0`, the version `lwk_wollet` 0.20
  uses, so crates depending on both no longer carry two `elements` versions.
- Bumped `electrum-client` from `0.25.0` to `0.25.2` (RUSTSEC-2026-0381);
  this moves `webpki-roots` to 1.0.11, which drops the compromised
  `emSign ECC Root CA - G3` from the bundled roots.
- Refreshed the compatible entries of `Cargo.lock`.

### Breaking
- `BtcSwapTx` and `LBtcSwapTx` gained a public `additional_outputs` field;
  struct-literal construction of these types must be updated (the
  constructors initialize it to an empty vector).
- `elements` types in the public API are now from `elements` 0.27; callers
  passing or receiving them must use `elements` 0.27.

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
