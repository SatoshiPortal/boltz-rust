use std::str::FromStr;

use lightning_invoice::Bolt11Invoice;

use crate::{
    e::{ErrorKind, S5Error},
    key::preimage::PreimageStates,
};

pub fn preimage_from_invoice_str(invoice_str: &str) -> Result<PreimageStates, S5Error> {
    let invoice = match Bolt11Invoice::from_str(&invoice_str) {
        Ok(invoice) => invoice,
        Err(e) => {
            println!("{:?}", e);
            return Err(S5Error::new(
                ErrorKind::Input,
                "Could not parse invoice string.",
            ));
        }
    };

    Ok(PreimageStates::from_sha256_str(
        &invoice.payment_hash().to_string(),
    ))
}
