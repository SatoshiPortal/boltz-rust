use bitcoin::bech32::{primitives::decode::CheckedHrpstring, NoChecksum};
use lightning::offers::invoice::Bolt12Invoice;

use crate::error::Error;

pub const BECH32_BOLT12_INVOICE_HRP: &str = "lni";
pub fn parse_bolt12_invoice(bolt12_invoice: &str) -> Result<Bolt12Invoice, Error> {
    let dec = match CheckedHrpstring::new::<NoChecksum>(bolt12_invoice) {
        Ok(dec) => dec,
        Err(err) => return Err(Error::Generic(format!("{err:?}"))),
    };
    if dec.hrp().to_lowercase() != BECH32_BOLT12_INVOICE_HRP {
        return Err(Error::Generic(format!("invalid hrp: {}", dec.hrp())));
    }

    let data = dec.byte_iter().collect::<Vec<_>>();
    lightning::offers::invoice::Bolt12Invoice::try_from(data)
        .map_err(|err| Error::Generic(format!("{err:?}")))
}
