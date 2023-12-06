# bullbitcoin-rnd

The goal of this project is to develop a working boltz client that supports:

- [ ] normal submarine swaps: Chain->LN for both Bitcoin & Liquid
Here we will pay an onchain script address for boltz and boltz will pay our LN invoice.

- [ ] reverse submarine swaps LN->Chain for both Bitcoin & Liquid
Here we will pay an LN invoice to boltz and boltz will fund an onchain script for us to sweep.


## Script

This requires building a `one-time use and dispose wallet` for the following bitcoin script (p2shwsh ONLY):

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

This script captures the following spending conditions:

```
Either; a preimage and the reciever's signature is required // happy case
Or; after a timeout the senders signature is required. // dispute
```

The `reciever` will be able to claim the funds on chain and in our case this would be us in case of a reverse swap and this would be boltz in case of a normal swap.

The `sender` will be able to claim funds on LN, once the reciever claims the onchain funds and reveals the preimage. This would be us in case of a normal swap and boltz in the case of a reverse swap.


## Procedure

There is no requirement for a database as we will not persist and data.

We simply create keys, build a script, generate a single address correspoding to this key, watch the address for a payment and spend the utxo by building a transaction, solving the spending conditions and broadcasting. We do not need to store transaction history or address indexes etc.

In case of `normal swaps`; the client (us) will ONLY be required to create the swap script and spend it in case boltz cheats and we need to claim back funds onchain from the script after a timeout. This will be a rare occurence. In the happy case, everything goes well, boltz pays our invoice and claims the onchain funds.
With reference to the above script, we would be the `sender` here; and can only spend after a timeout incase of a dispute.

In case of `reverse swaps`; the client (us) will ALWAYS be required to build and spend from the script to claim onchain funds. With reference to the above script, we would be the `receiver` here; and the solution to the reverse swap is the `preimage` of a hash and a `signature` from a key.

For the most parts, normal swaps only requires interaction with the boltz.exchange api, making it quite straight forward. In case of a dispute and we need to claim back funds, we will need to build the script and spend it. 

For the sake of simplification, we will look at the standard procedure when doing a `reverse swap` as it is more involved.

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
- [ ] boltz will confirm `invoice` paid and send funds to the `address` creating a utxo that we can spend
- [ ] construct a transaction to spend this utxo
- [ ] solve spending conditions: hashlock + signature
- [ ] sweep the utxo to your existing bitcoin wallet
- [ ] once the utxo is spent, the preimage is publically revealed and boltz can now claim the `invoice` 

### Liquid (UTXO Chain)

The swap procedure will be similar for liquid with a few additions like using a blindingKey for confidential transactions.

The elements library is very similar to bitcoin and solving this problem for bitcoin will also solve majority of the problem for liquid.

Additionally, this repo will also explore using `bewallet` as an option for bullbitcoin's primary Liquid wallet.

## Core Libraries/API

- [boltz](https://docs.boltz.exchange/v/api/api)
- [bitcoin](https://docs.rs/bitcoin/0.30.0/bitcoin/index.html)
- [elements](https://docs.rs/elements/0.22.0/elements/index.html)
- [lightning-invoice](https://docs.rs/lightning-invoice/latest/lightning_invoice/)
- [bewallet](https://github.com/LeoComandini/BEWallet/tree/master)

## Resources

- [teleport](https://github.com/bitcoin-teleport/teleport-transactions)
A script wallet for coinswap

- [bitcoin-wallet](https://github.com/rust-bitcoin/rust-wallet)
A simple rust bitcoin wallet

- [rust-bitcoin-wallet](https://github.com/stevenroose/rust-bitcoin-wallet)
Another old simple rust bitcoin wallet

## test

```bash
cargo test
cargo test -- --nocapture # for logs
```

`test_*_swap` is ignored by default, always keep them ignored and run the test manually. 

To run `test_normal_swap`, make sure to upadate the `invoice`.

`swapstatus` is tested within `test_*_swap`, however a separate test exists to manually test your swap' status through its lifetime.

This is also ignored, to run it, make sure you update the `id` accordingly.

