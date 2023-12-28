# boltz-client

The goal of this  is to develop a working boltz client in rust that supports:

- [x] normal submarine swaps: OnChain->LN for both Bitcoin & Liquid
Here we will pay an onchain script address for boltz and boltz will pay our LN invoice.

- [ ] reverse submarine swaps LN->OnChain for both Bitcoin & Liquid
Here we will pay an LN invoice to boltz and boltz will fund an onchain script for us to sweep.

## Script

This requires building a `one-time use and dispose wallet` for the following bitcoin script:

BOLTZ NORMAL SWAP: p2shwsh

```
    HASH160 <hash of the preimage> 
    EQUAL
    IF <reciever public key>
    ELSE <timeout block height> 
    CHECKLOCKTIMEVERIFY
    DROP <sender public key> 
    ENDIF
    CHECKSIG
```

BOLTZ REVERSE SWAP: p2sh

```
    SIZE
    [32]
    EQUAL
    IF
    HASH160 <hash of the preimage>
    EQUALVERIFY <reciever public key>
    ELSE
    DROP <timeout block height>
    CLTV
    DROP <sender public key> 
    ENDIF
    CHECKSIG
```

This script captures the following spending conditions:

```
Either; a preimage and the reciever's signature is required // happy case (claimTx)
Or; after a timeout the senders signature is required. // dispute (refundTx)
```

The `reciever` will be able to claim the funds on chain,
We are the reciever in case of a reverse swap and this would be boltz in case of a normal swap.

The `sender` will be able to claim funds on LN, once the reciever claims the onchain funds and reveals the preimage. 
We are the sender in case of a normal swap and boltz in the case of a reverse swap.

## Procedure

There is no requirement for a database as we will not persist and data.

We simply create keys, build a script, generate a single address correspoding to this key, watch the address for a payment and spend the utxo by building a transaction, solving the spending conditions and broadcasting. 
We do not need to store transaction history or address indexes etc. This has to be handled by the client. 

The client must ensure that they are rotating the keys and preimages being used. There are helper structs and methods for this.

In case of `normal swaps`; In the happy case, everything goes well, boltz pays our invoice and claims the onchain funds.
The client (us) will ONLY be required to create the swap script and spend it in case boltz cheats and we need to claim back funds onchain from the script after a timeout. 
We would be the `sender`; and can only spend after a timeout incase of a dispute.

In case of `reverse swaps`; In the happy case, the client (us) will ALWAYS be required to build and spend from the script to claim onchain funds. 
We would be the `receiver` ; and the solution we have to create to the reverse swap is the `preimage` of a hash and a `signature` from our key.

For the most parts, normal swaps only requires interaction with the boltz.exchange api, making it quite straight forward. In case of a dispute and we need to claim back funds, we will need to build the script and spend it.

For the sake of unifying the implementation challenge, we will look at the standard procedure when doing a `reverse swap` happy case.

- [x] Create a `keypair.{seckey,pubkey}`
- [x] Create a random secret (preimage)
- [x] Create `hash`=sha256(preimage)
- [x] Share `keypair.pubkey` and `hash` with boltz.exchange
- [x] boltz will use use this to create the script on their end and send it back to us as a `redeem_script` along with an LN `invoice` for us to pay and an onchain `address` that they will fund for us to claim
- [x] boltz will also return their `pubkey` and the `timeout` used
- [x] verify the response from boltz and the preimage used in the invoice (boltz cannot claim the invoice until the preimage is known)
- [x] build the script on our end using: `our_pubkey, hash, boltz_pubkey and timeout`
- [x] generate address from the script and check for a match against the `address` provided by boltz
- [x] ensure our script matches the `redeemScript` provided by boltz
- [x] pay the `invoice` (use local clightning)
- [x] boltz will confirm `invoice` paid and send funds to the `address` creating a utxo that we can spend
- [x] construct a transaction/psbt to spend this utxo
- [x] solve spending conditions: hashlock + signature
- [x] sweep the utxo to your existing bitcoin wallet
- [x] once the utxo is spent, the preimage is publically revealed and boltz can now claim the `invoice`

### Liquid (WIP)

The swap procedure will be similar for liquid with a few additions like using a blindingKey for confidential transactions.

The elements library is very similar to bitcoin and solving this problem for bitcoin will also solve majority of the problem for liquid.

## Core Libraries/API

- [boltz](https://docs.boltz.exchange/v/api/api)
- [bitcoin](https://docs.rs/bitcoin/0.30.0/bitcoin/index.html)
- [elements](https://docs.rs/elements/0.22.0/elements/index.html)
- [lightning-invoice](https://docs.rs/lightning-invoice/latest/lightning_invoice/)
- [electrum-client](https://docs.rs/electrum-client/latest/electrum_client/)

## Resources

- [teleport](https://github.com/bitcoin-teleport/teleport-transactions)
A script wallet for coinswap

- [bitcoin-wallet](https://github.com/rust-bitcoin/rust-wallet)
A simple rust bitcoin wallet

- [rust-bitcoin-wallet](https://github.com/stevenroose/rust-bitcoin-wallet)
Another old simple rust bitcoin wallet - only upto Psbt building

- [boltz](https://github.com/BoltzExchange/boltz-core/blob/master/lib/swap/Claim.ts)
Boltz-core - solving the claim script

- [tdryja-ct](https://www.youtube.com/watch?v=UySc4jxbqi4)
Tadge Dryja's MIT Opencourseware presentation on Confidential Transactions

## test

The best place to start diving into this repo is `tests` directory. This contains integration tests for bitcoin and liquid.

They contain the entire example of usage of the library. 

Run all tests, except ignored tests

```bash
./test # test helper script
# OR MANUALLY
cargo test
cargo test -- --nocapture # for println! logs
```

### ignored tests

To run complete reverse swap integration test: 

```bash
cargo test test_rsi -- --nocapture 
```
`test_rsi` is interactive. 
It will block the terminal and prompt you to pay a ln invoice to proceed.


```bash
cargo test test_normal_swap -- --nocapture 

```
`test_normal_swap` is ignored since it requires always using a new invoice or else it errors with 409

So when manually testing, make sure you update the invoice variable.

For all ignored unit tests read the tests before running.


## Milestones

- [x] NormalSwap  (BTC): Claim (Invoice paid)
- [ ] NormalSwap  (BTC): Refund
- [x] ReverseSwap (BTC): Claim
- [x] ReverseSwap (BTC): Refund (Invoice expires)
- [x] NormalSwap  (L-BTC): Claim (Invoice paid)
- [ ] NormalSwap  (L-BTC): Refund
- [ ] ReverseSwap (L-BTC): Claim
- [x] ReverseSwap (L-BTC): Refund (Invoice expires)
