use bech32::FromBase32;
use lightning::offers::invoice::Bolt12Invoice;

use crate::error::Error;

const BECH32_BOLT12_INVOICE_HRP: &str = "lni";
pub fn parse_bolt12_invoice(bolt12_invoice: &str) -> Result<Bolt12Invoice, Error> {
    // TODO: for some reason, upstream Bolt12Invoice::from_str is not supported, thus we do it manually
    let (hrp, data) = bech32::decode_without_checksum(bolt12_invoice)
        .map_err(|e| Error::Generic(e.to_string()))?;
    if hrp.as_str() != BECH32_BOLT12_INVOICE_HRP {
        return Err(Error::Generic(format!("invalid hrp: {hrp}")));
    }

    let data = Vec::<u8>::from_base32(&data).map_err(|e| Error::Generic(e.to_string()))?;
    lightning::offers::invoice::Bolt12Invoice::try_from(data)
        .map_err(|e| Error::Generic(format!("{e:?}")))
}
