use crate::error::Error;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::{lnurl::LnUrl, Builder, LnUrlResponse};
use std::str::FromStr;

pub fn fetch_invoice(address: &str, amount_msats: u64) -> Result<String, Error> {
    let lnurl = match LnUrl::from_str(address) {
        Ok(lnurl) => lnurl,
        Err(_) => match LightningAddress::from_str(address) {
            Ok(lightning_address) => lightning_address.lnurl(),
            Err(_) => {
                return Err(Error::Generic(
                    "Not a valude LnUrl or LnAddress".to_string(),
                ))
            }
        },
    };

    let client = Builder::default()
        .build_blocking()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let res = client
        .make_request(&lnurl.url.to_lowercase())
        .map_err(|e| Error::HTTP(e.to_string()))?;

    match res {
        LnUrlResponse::LnUrlPayResponse(pay) => {
            let pay_result = client
                .get_invoice(&pay, amount_msats, None, None)
                .map_err(|e| Error::HTTP(e.to_string()))?;
            let invoice =
                Bolt11Invoice::from_str(pay_result.invoice()).map_err(|e| Error::Bolt11(e))?;

            if invoice.amount_milli_satoshis() != Some(amount_msats) {
                return Err(Error::Generic(
                    "Invoice amount doesn't match requested amount".to_string(),
                ));
            }

            Ok(pay_result.invoice().to_string())
        }
        _ => Err(Error::Generic("Unexpected response type".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(address: &str, amount_msats: u64, format: &str) {
        let result = fetch_invoice(address, amount_msats);

        match result {
            Ok(invoice) => {
                assert!(!invoice.is_empty(), "Invoice should not be empty");
                assert!(
                    invoice.starts_with("lnbc"),
                    "Invoice should start with 'lnbc'"
                );
                println!("Successfully fetched invoice, format : {}", format)
            }
            Err(e) => {
                println!("Error occured with {} format: {}", format, e.message());
            }
        }
    }

    #[test]
    fn test_fetch_invoice() {
        let amount_msats = 100000;
        let lnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns";
        let uppercase_lnurl = lnurl.to_uppercase();

        test_address(lnurl, amount_msats, "LNURL");
        test_address(&uppercase_lnurl, amount_msats, "LNURL");

        let email_lnurl = "drunksteel17@walletofsatoshi.com";
        test_address(email_lnurl, amount_msats, "Lightning Address");
    }
}
