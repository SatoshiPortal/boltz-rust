/* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */
use boltz_client::{swaps::boltz::SwapType, util::error::S5Error};

use crate::secrets::KeyPair;

pub struct Api {}

impl Api {
    pub fn keypair_from_mnemonic(
        mnemonic: String,
        index: u64,
        swap_type: SwapType,
    ) -> Result<KeyPair, S5Error> {
        KeyPair::new(mnemonic, index, swap_type)
    }
}

// flutter_rust_bridge_codegen --rust-input rust/src/api.rs --dart-output lib/bridge_generated.dart --dart-decl-output lib/bridge_definitions.dart
