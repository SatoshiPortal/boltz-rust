import asyncio
import boltz_client
from common import *


async def swap(
    from_chain: boltz_client.Chain, to_chain: boltz_client.Chain, refund: bool = False
):
    claim_address = await getnewaddress(to_chain)

    ws_client = boltz_api.ws()
    claim_keys = boltz_client.KeyPair()
    refund_keys = boltz_client.KeyPair()
    amount = 1000000
    preimage = boltz_client.Preimage()
    request = boltz_client.CreateChainRequest(
        _from=from_chain,
        to=to_chain,
        preimage_hash=preimage.sha256(),
        claim_public_key=claim_keys.public(),
        refund_public_key=refund_keys.public(),
        user_lock_amount=amount,
    )

    response = await boltz_api.create_chain_swap(request)
    swap_id = response.id

    asyncio.create_task(ws_client.run_ws_loop())

    lockup_script = boltz_client.SwapScript.from_chain(
        chain=from_chain,
        side=boltz_client.Side.LOCKUP,
        chain_swap_details=response.lockup_details,
        our_pubkey=refund_keys.public(),
    )

    claim_script = boltz_client.SwapScript.from_chain(
        chain=to_chain,
        side=boltz_client.Side.CLAIM,
        chain_swap_details=response.claim_details,
        our_pubkey=claim_keys.public(),
    )

    # Monitor the swap status via WebSocket
    await ws_client.subscribe_swap(swap_id)
    updates = ws_client.updates()

    await next_status(updates, "swap.created")

    # Send amount based on whether we're testing refund or not
    send_amount = amount // 2 if refund else amount
    await sendtoaddress(from_chain, response.lockup_details.lockup_address, send_amount)

    if refund:
        await next_status(updates, "transaction.lockupFailed")

        await delay()

        refund_address = await getnewaddress(from_chain)

        refund_params = boltz_client.SwapTransactionParams(
            output_address=refund_address,
            fee=boltz_client.Fee.ABSOLUTE(200),
            swap_id=swap_id,
            keys=refund_keys,
            chain_client=chain_client,
            boltz_client=boltz_api,
        )

        refund_tx = await lockup_script.construct_refund(refund_params)
        txid = await chain_client.broadcast_tx(refund_tx)
        print(f"Refund Transaction ID: {txid}")
        assert txid is not None
    else:
        await next_status(updates, "transaction.mempool")
        await mine_block()

        await next_status(updates, "transaction.confirmed")

        await next_status(updates, "transaction.server.mempool")
        await mine_block()

        await next_status(updates, "transaction.server.confirmed")
        await delay()

        claim_params = boltz_client.SwapTransactionParams(
            output_address=claim_address,
            fee=boltz_client.Fee.ABSOLUTE(200),
            swap_id=swap_id,
            keys=claim_keys,
            chain_client=chain_client,
            boltz_client=boltz_api,
            options=boltz_client.TransactionOptions(
                chain_claim=boltz_client.ChainClaim(
                    keys=refund_keys, lockup_script=lockup_script
                )
            ),
        )

        claim_tx = await claim_script.construct_claim(preimage, claim_params)
        txid = await chain_client.broadcast_tx(claim_tx)
        print(f"Claim Transaction ID: {txid}")


async def main():
    await swap(btc_chain, lbtc_chain, False)
    await swap(lbtc_chain, btc_chain, False)
    await swap(btc_chain, lbtc_chain, True)
    await swap(lbtc_chain, btc_chain, True)


if __name__ == "__main__":
    asyncio.run(main())
