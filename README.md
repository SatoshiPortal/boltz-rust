# bullbitcoin-rnd

The goal of this project is to develop a working boltz client that supports:

- [] normal submarine swaps: Chain->LN for both Bitcoin & Liquid
- [] reverse submarine swaps LN->Chain for both Bitcoin & Liquid

This requires building a one-time use wallet for the following bitcoin script:

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

In case of normal swaps; the client will ONLY be required to create the swap script spend in case boltz cheats and we need to claim back funds from the script after a timeout. This will be a rare occurence.

In case of reverse swaps; the client will ALWAYS be required to build and spend from the script to claim back onchain funds.

## Procedure

For the most parts, normal swaps only requires interaction with the boltz.exchange api, making it quite straight forward. In case of a dispute and we need to claim back funds, we will need to build the script and spend it. 

For the sake of simplification, we will look at the standard procedure when doing a reverse swap.

- Create a `keypair.{seckey,pubkey}`
- Create a random secret (preimage)
- Create `hash`=sha256(preimage)
- Share `keypair.pubkey` and `hash` with boltz.exchange
- boltz will use use this to create the script on their end and send it back to us as a `redeem_script` along with an LN `invoice` for us to pay and an onchain `address` that they will fund for us to claim
- boltz will also return their `pubkey` and the `timeout` used
- verify the response from boltz and the preimage used in the invoice (boltz cannot claim the invoice until the preimage is known)
- build the script on our end using: `our_pubkey, hash, boltz_pubkey and timeout`
- generate address from the script and check for a match against the `address` provided by boltz
- ensure our script matches the `redeemScript` provided by boltz
- pay the `invoice`
- boltz will confirm `invoice` paid and send funds to the `address` creating a utxo that we can spend
- once confirmed, construct a transaction to spend this utxo
- spend the utxo to your existing bitcoin wallet
- once the utxo is spent, the preimage is publically revealed and boltz can now claim the `invoice` 


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

# test

```bash
cargo test
cargo test -- --nocapture # for logs
```

`test_*_swap` is ignored by default, always keep them ignored and run the test manually. 

To run `test_normal_swap`, make sure to upadate the `invoice`.

`swapstatus` is tested within `test_*_swap`, however a separate test exists to manually test your swap' status through its lifetime.

This is also ignored, to run it, make sure you update the `id` accordingly.

