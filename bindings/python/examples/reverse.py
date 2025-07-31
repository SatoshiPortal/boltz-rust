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
    boltz_api = boltz_client.BoltzApiClientV2.default(network)

    to_chain = boltz_client.btc_chain_from_network(network)

    # Initialize WebSocket client
    ws_client = boltz_api.ws()

    # Generate a new key pair for the swap
    key_pair = boltz_client.KeyPair()

    # Get the amount to swap from user
    amount = int(input("Enter amount in sats to swap: "))

    claim_address = input(
        f"Enter claim address for {'liquid' if to_chain.is_liquid() else 'bitcoin'}: "
    )

    preimage = boltz_client.Preimage()

    # Create a reverse swap request
    request = boltz_client.CreateReverseRequest(
        invoice_amount=amount,
        _from=to_chain,
        to=to_chain,
        preimage_hash=preimage.sha256(),
        claim_public_key=key_pair.public(),
    )

    print("\n=== Creating Reverse Swap ===")
    response = await boltz_api.create_reverse_swap(request)
    swap_id = response.id
    print(f"Swap ID: {swap_id}")
    print(f"Lockup Address: {response.lockup_address}")
    print(f"Lightning Invoice: {response.invoice}")

    print("\n=== Instructions ===")
    print("1. Pay the Lightning invoice above")
    print("2. Wait for the swap to be confirmed")
    print("3. The funds will be sent to your lockup address automatically")
    print("\nMonitoring swap status via WebSocket...")

    asyncio.create_task(ws_client.run_ws_loop())

    # Monitor the swap status via WebSocket
    await ws_client.subscribe_swap(swap_id)
    updates = ws_client.updates()
    while True:
        update = await updates.next()
        status = update.status

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Swap Status: {status}")

        if status == "swap.created":
            print("\n=== Action Required ===")
            print(f"Please pay the Lightning invoice: {response.invoice}")
            print("Waiting for your payment...")

        elif status == "transaction.mempool":
            print("Transaction detected in mempool!")
            print("Waiting for transaction to be confirmed... (mine a block)")

        elif status == "transaction.confirmed":
            print("Lockup transaction confirmed!")

            swap_script = boltz_client.SwapScript.from_reverse(
                chain=to_chain, reverse_response=response, our_pubkey=key_pair.public()
            )

            tx = await swap_script.construct_claim(
                preimage,
                boltz_client.SwapTransactionParams(
                    swap_id=swap_id,
                    keys=key_pair,
                    fee=boltz_client.Fee.ABSOLUTE(200),
                    output_address=claim_address,
                    chain_client=chain_client,
                    boltz_client=boltz_api,
                ),
            )

            print("Transaction signed, broadcasting...")
            tx_id = await chain_client.broadcast_tx(tx)
            print(f"Transaction ID: {tx_id}")

        elif status == "invoice.settled":
            print("\n=== Success! ===")
            print("Swap completed successfully!")
            print(f"Funds have been sent to {claim_address}")
            break

        elif status in ["transaction.lockupFailed", "invoice.failedToPay"]:
            print("\n=== Swap Failed ===")
            print("The swap could not be completed")
            break

        elif status == "expired":
            print("\n=== Swap Expired ===")
            print("The swap has expired")
            break


if __name__ == "__main__":
    asyncio.run(main())
