/*

THIS WILL MOVE TO ITS OWN boltz-client-flutter repository

*/
struct BoltzBtcSwap {
    kind: SwapType,
    network: BitcoinNetwork,
    electrum_url: String,
    boltz_url: String,
    id: String,
    script: BtcSwapScript,
    tx: BtcSwapTx,
    boltz_hold_invoice: String,
    output_value: u64,
}

trait BoltzSwapWallet {
    pub fn get_fees(boltz_url: String) -> f32 {
        /*
         *
         * Get current fees from boltz.excahnge
         *
         */
    }
    pub fn new_submarine(
        network: BitcoinNetwork,
        electrum_url: String,
        boltz_url: String,
        refund_keypair: KeyPairString,
        invoice: String,
    ) -> Result<Self, Error> {
        /*
         *
         * Create secrets
         * Create a swap on boltz
         * Construct swap script and validate boltz response
         *
         */
    }
    pub fn new_reverse(
        network: BitcoinNetwork,
        electrum_url: String,
        boltz_url: String,
        claim_keypair: KeyPairString,
        preimage: PreimageStates,
        output_value: u64,
    ) -> Result<Self, Error> {
        /*
         *
         * Create secrets
         * Create a swap on boltz
         * Construct swap script and validate boltz response
         * Construct an swap tx
         *
         */
    }
    pub fn payment_details(&self) -> (String, u64) {
        /*
         *
         * For Submarine => (lockupaddress, output_value)
         * For Reverse => (boltz_hold_invoice, 0)
         *
         *
         */
    }
    pub fn status(&self) -> SwapStatus {
        /*
         *
         * Api call GET status from boltz.exchange
         * Check script balance for reverse swap
         *
         */
    }
    pub fn claim(&self, output_address: String, absolute_fees: String) -> String {
        /*
         *
         * Reverse => Sign Tx & Broadcast
         * Submarine => N/A
         *
         */
    }
    pub fn refund(&self, output_address: String, absolute_fees: String) -> String {
        /*
         *
         * Submarine => Sign Tx & Broadcast
         * Reverse =>N/A
         *
         */
    }
}

mod tests {
    #[test]
    fn test_api() {
        let fees = BoltzBtcSwap::get_fees();
        // if user accepts fee, they can start a swap
        let boltz_swap = BoltzBtcSwap::new_submarine();
        boltzs_swap.get_payment_details();
        boltz_swap.get_status();
        let boltz_swap = BoltzBtcSwap::new_reverse();
        boltzs_swap.get_payment_details();
        boltz_swap.get_status();
        boltz_swap.claim();
    }
}
