import boltz_client
import asyncio
from datetime import datetime

electrum_btc = boltz_client.ClientConnection.ELECTRUM(
    boltz_client.ElectrumBuilder(url="localhost:19001", tls=False)
)
electrum_lbtc = boltz_client.ClientConnection.ELECTRUM(
    boltz_client.ElectrumBuilder(url="localhost:19002", tls=False)
)
network = boltz_client.Network.REGTEST
chain_client = boltz_client.ChainClient(
    boltz_client.ClientConfig(
        network=network, bitcoin=electrum_btc, liquid=electrum_lbtc
    )
)


async def main():
    # Initialize the Boltz API client
    network = boltz_client.Network.REGTEST
    btc_chain = boltz_client.btc_chain_from_network(network)
    boltz_api = boltz_client.BoltzApiClientV2.default(network)

    # Initialize WebSocket client
    ws_client = boltz_api.ws()

    # Generate a new key pair for the swap
    key_pair = boltz_client.KeyPair()

    # Create a submarine swap request
    # Note: Replace this with your actual Lightning invoice
    invoice = input("Enter your Lightning invoice: ")

    request = boltz_client.CreateSubmarineRequest(
        _from=btc_chain,
        to=btc_chain,
        invoice=invoice,
        refund_public_key=key_pair.public(),
    )

    print("\n=== Creating Submarine Swap ===")
    swap_response = await boltz_api.create_swap(request)
    swap_id = swap_response.id
    print(f"Swap ID: {swap_id}")
    print(f"Expected Amount: {swap_response.expected_amount} sats")
    print(f"Lockup Address: {swap_response.address}")

    lockup_script = boltz_client.SwapScript.from_submarine(
        chain=btc_chain,
        create_swap_response=swap_response,
        our_pubkey=key_pair.public(),
    )

    print("\n=== Instructions ===")
    print("1. Send EXACTLY the expected amount to the lockup address above")
    print("2. Wait for the swap to be confirmed")
    print("3. The Lightning invoice will be paid automatically")
    print("\nMonitoring swap status via WebSocket...")

    asyncio.create_task(ws_client.run_ws_loop())

    # Monitor the swap status via WebSocket
    await ws_client.subscribe_swap(swap_id)
    updates = ws_client.updates()
    while True:
        update = await updates.next()
        status = update.status

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Swap Status: {status}")

        if status == "invoice.set":
            print("\n=== Action Required ===")
            print(
                f"Please send {swap_response.expected_amount} sats to {swap_response.address}"
            )
            print("Waiting for your transaction...")

        elif status == "transaction.mempool":
            print("Transaction detected in mempool!")

        elif status == "transaction.claim.pending":
            print("Signing cooperative claim for boltz...")
            await lockup_script.submarine_cooperative_claim(
                swap_id, key_pair, invoice, boltz_api
            )

        elif status == "transaction.claimed":
            print("\n=== Success! ===")
            print("Swap completed successfully!")
            print("Your Lightning invoice has been paid")
            break

        elif status in ["transaction.lockupFailed", "invoice.failedToPay"]:
            print("\n=== Swap Failed ===")
            print("The swap could not be completed")

            refund_address = input("Enter your refund address: ")

            tx = await lockup_script.construct_refund(
                boltz_client.SwapTransactionParams(
                    output_address=refund_address,
                    fee=boltz_client.Fee.ABSOLUTE(200),
                    swap_id=swap_id,
                    keys=key_pair,
                    chain_client=chain_client,
                    boltz_client=boltz_api,
                )
            )

            txid = await chain_client.broadcast_tx(tx)
            print(f"Refund Transaction ID: {txid}")
            break

        elif status == "expired":
            print("\n=== Swap Expired ===")
            print("The swap has expired")
            break


if __name__ == "__main__":
    asyncio.run(main())
