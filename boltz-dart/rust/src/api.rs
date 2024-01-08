/* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use crate::secrets::KeyPair;

use crate::boltzswap::BoltzSwapType;
use crate::error::BoltzError;

// pub type BoltzError = boltz_client::util::error::S5Error;
pub struct Api {}

impl Api {
    pub fn keypair_from_mnemonic(
        mnemonic: String,
        index: u64,
        swap_type: BoltzSwapType,
    ) -> Result<KeyPair, BoltzError> {
        match KeyPair::new(mnemonic, index, swap_type.into()) {
            Ok(keypair) => Ok(keypair),
            Err(err) => Err(err.into()),
        }
    }
}

// flutter_rust_bridge_codegen --rust-input rust/src/api.rs --dart-output lib/bridge_generated.dart --dart-decl-output lib/bridge_definitions.dart
