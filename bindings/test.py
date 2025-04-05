import boltz_client
import asyncio
from datetime import datetime


async def main():
    # Initialize the Boltz API client
    # Note: In production, use the mainnet URL instead of localhost
    api_url = "http://localhost:9001/v2"
    client = boltz_client.BoltzApiClientV2(api_url, 3)
    
    # Initialize WebSocket client
    ws_client = client.ws()
    
    # Generate a new key pair for the swap
    key_pair = boltz_client.KeyPair()
    
    # Create a submarine swap request
    # Note: Replace this with your actual Lightning invoice
    invoice = input("Enter your Lightning invoice: ")
    
    request = boltz_client.CreateSubmarineRequest(
        _from='BTC',
        to='BTC',
        invoice=invoice,
        refund_public_key=key_pair.public(),
        pair_hash=None,
        referral_id=None
    )

    # Create the swap
    print("\n=== Creating Submarine Swap ===")
    swap_response = await client.post_swap_req(request)
    swap_id = swap_response.id
    print(f"Swap ID: {swap_id}")
    print(f"Expected Amount: {swap_response.expected_amount} sats")
    print(f"Lockup Address: {swap_response.address}")
    
    # Print instructions for the user
    print("\n=== Instructions ===")
    print("1. Send EXACTLY the expected amount to the lockup address above")
    print("2. Wait for the swap to be confirmed")
    print("3. The Lightning invoice will be paid automatically")
    print("\nMonitoring swap status via WebSocket...")

    asyncio.create_task(ws_client.run_ws_loop())

    # Subscribe to WebSocket updates for this swap
    await ws_client.subscribe(swap_id)
    
    # Get the updates channel
    updates = ws_client.updates()
    
    # Monitor the swap status via WebSocket
    while True:
        update = await updates.next()
        status = update.status
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Swap Status: {status}")
        
        if status == "invoice.set":
            print("\n=== Action Required ===")
            print(f"Please send {swap_response.expected_amount} sats to {swap_response.address}")
            print("Waiting for your transaction...")
            
        elif status == "transaction.mempool":
            print("Transaction detected in mempool!")
            
        elif status == "transaction.claimed":
            print("\n=== Success! ===")
            print("Swap completed successfully!")
            print("Your Lightning invoice has been paid")
            break
            
        elif status in ["transaction.lockupFailed", "invoice.failedToPay"]:
            print("\n=== Swap Failed ===")
            print("The swap could not be completed")
            print("You may need to refund your transaction")
            break
            
        elif status == "expired":
            print("\n=== Swap Expired ===")
            print("The swap has expired")
            break


if __name__ == "__main__":
    asyncio.run(main())
