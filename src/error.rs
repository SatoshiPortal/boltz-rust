/// The Global Error enum. Encodes all possible internal library errors
#[derive(Debug)]
pub enum Error {
    Electrum(electrum_client::Error),
    Hex(String),
    Protocol(String),
    Key(bitcoin::key::Error),
    Address(String),
    Sighash(bitcoin::sighash::Error),
    Secp(bitcoin::secp256k1::Error),
    HTTP(ureq::Error),
    JSON(serde_json::Error),
    IO(std::io::Error),
    Bolt11(lightning_invoice::ParseOrSemanticError),
    LiquidEncode(elements::encode::Error),
    Blind(String),
    ConfidentialTx(elements::ConfidentialTxOutError),
    BIP32(bitcoin::bip32::Error),
    BIP39(bip39::Error),
    Hash(bitcoin::hashes::FromSliceError),
    Locktime(String),
    Url(url::ParseError),
    WebSocket(tungstenite::Error),
    Taproot(String),
    Musig2(String),
}

impl From<electrum_client::Error> for Error {
    fn from(value: electrum_client::Error) -> Self {
        Self::Electrum(value)
    }
}

impl From<bitcoin::hex::HexToBytesError> for Error {
    fn from(value: bitcoin::hex::HexToBytesError) -> Self {
        Self::Hex(value.to_string())
    }
}

impl From<bitcoin::key::Error> for Error {
    fn from(value: bitcoin::key::Error) -> Self {
        Self::Key(value)
    }
}

impl From<bitcoin::hex::HexToArrayError> for Error {
    fn from(value: bitcoin::hex::HexToArrayError) -> Self {
        Self::Hex(value.to_string())
    }
}

impl From<bitcoin::address::ParseError> for Error {
    fn from(value: bitcoin::address::ParseError) -> Self {
        Self::Address(value.to_string())
    }
}

impl From<elements::address::AddressError> for Error {
    fn from(value: elements::address::AddressError) -> Self {
        Self::Address(value.to_string())
    }
}

impl From<bitcoin::sighash::Error> for Error {
    fn from(value: bitcoin::sighash::Error) -> Self {
        Self::Sighash(value)
    }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(value: bitcoin::secp256k1::Error) -> Self {
        Self::Secp(value)
    }
}

impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Self::HTTP(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::JSON(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<lightning_invoice::ParseOrSemanticError> for Error {
    fn from(value: lightning_invoice::ParseOrSemanticError) -> Self {
        Self::Bolt11(value)
    }
}

impl From<elements::hex::Error> for Error {
    fn from(value: elements::hex::Error) -> Self {
        Self::Hex(value.to_string())
    }
}

impl From<elements::encode::Error> for Error {
    fn from(value: elements::encode::Error) -> Self {
        Self::LiquidEncode(value)
    }
}

impl From<elements::BlindError> for Error {
    fn from(value: elements::BlindError) -> Self {
        Self::Blind(value.to_string())
    }
}

impl From<elements::UnblindError> for Error {
    fn from(value: elements::UnblindError) -> Self {
        Self::Blind(value.to_string())
    }
}

impl From<elements::ConfidentialTxOutError> for Error {
    fn from(value: elements::ConfidentialTxOutError) -> Self {
        Self::ConfidentialTx(value)
    }
}

impl From<bitcoin::bip32::Error> for Error {
    fn from(value: bitcoin::bip32::Error) -> Self {
        Self::BIP32(value)
    }
}

impl From<bitcoin::hashes::FromSliceError> for Error {
    fn from(value: bitcoin::hashes::FromSliceError) -> Self {
        Self::Hash(value)
    }
}

impl From<bip39::Error> for Error {
    fn from(value: bip39::Error) -> Self {
        Self::BIP39(value)
    }
}

impl From<bitcoin::absolute::Error> for Error {
    fn from(value: bitcoin::absolute::Error) -> Self {
        Self::Locktime(value.to_string())
    }
}

impl From<elements::locktime::Error> for Error {
    fn from(value: elements::locktime::Error) -> Self {
        Self::Locktime(value.to_string())
    }
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self {
        Self::Url(value)
    }
}

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        Self::WebSocket(value)
    }
}

impl From<bitcoin::taproot::TaprootError> for Error {
    fn from(value: bitcoin::taproot::TaprootError) -> Self {
        Self::Taproot(value.to_string())
    }
}

impl From<elements::taproot::TaprootError> for Error {
    fn from(value: elements::taproot::TaprootError) -> Self {
        Self::Taproot(value.to_string())
    }
}

impl From<elements::taproot::TaprootBuilderError> for Error {
    fn from(value: elements::taproot::TaprootBuilderError) -> Self {
        Self::Taproot(value.to_string())
    }
}

impl From<bitcoin::taproot::TaprootBuilderError> for Error {
    fn from(value: bitcoin::taproot::TaprootBuilderError) -> Self {
        Self::Taproot(value.to_string())
    }
}

impl From<elements::secp256k1_zkp::MusigTweakErr> for Error {
    fn from(value: elements::secp256k1_zkp::MusigTweakErr) -> Self {
        Self::Musig2(value.to_string())
    }
}

impl From<elements::secp256k1_zkp::MusigNonceGenError> for Error {
    fn from(value: elements::secp256k1_zkp::MusigNonceGenError) -> Self {
        Self::Musig2(value.to_string())
    }
}

impl From<elements::secp256k1_zkp::ParseError> for Error {
    fn from(value: elements::secp256k1_zkp::ParseError) -> Self {
        Self::Musig2(value.to_string())
    }
}

impl From<elements::secp256k1_zkp::MusigSignError> for Error {
    fn from(value: elements::secp256k1_zkp::MusigSignError) -> Self {
        Self::Musig2(value.to_string())
    }
}
