use bitcoin::bech32::{primitives::decode::CheckedHrpstring, NoChecksum};
use lightning::offers::invoice::Bolt12Invoice;

use crate::error::Error;

const BECH32_BOLT12_INVOICE_HRP: &str = "lni";

pub(crate) fn decode_invoice(invoice: &str) -> Result<Bolt12Invoice, Error> {
    let dec = match CheckedHrpstring::new::<NoChecksum>(invoice) {
        Ok(dec) => dec,
        Err(err) => return Err(Error::Bolt12(format!("{:?}", err))),
    };
    if dec.hrp().to_lowercase() != BECH32_BOLT12_INVOICE_HRP {
        return Err(Error::Bolt12("invalid HRP".to_string()));
    }

    let data = dec.byte_iter().collect::<Vec<_>>();
    Bolt12Invoice::try_from(data).map_err(|e| Error::Bolt12(format!("{:?}", e)))
}
