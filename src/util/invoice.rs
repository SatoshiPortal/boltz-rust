use crate::error::Error;
use crate::util::bolt12::{parse_bolt12_invoice, BECH32_BOLT12_INVOICE_HRP};
use lightning::offers::invoice::Bolt12Invoice;
use lightning_invoice::Bolt11Invoice;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub enum LightningInvoice {
    Bolt11(Box<Bolt11Invoice>),
    Bolt12(Box<Bolt12Invoice>),
}

impl LightningInvoice {
    pub fn payment_hash(&self) -> String {
        match self {
            LightningInvoice::Bolt11(i) => i.payment_hash().to_string(),
            LightningInvoice::Bolt12(i) => i.payment_hash().to_string(),
        }
    }
}

impl FromStr for LightningInvoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_lowercase().starts_with(BECH32_BOLT12_INVOICE_HRP) {
            Ok(LightningInvoice::Bolt12(Box::new(parse_bolt12_invoice(s)?)))
        } else {
            Ok(LightningInvoice::Bolt11(Box::new(
                Bolt11Invoice::from_str(s).map_err(Error::Bolt11)?,
            )))
        }
    }
}
