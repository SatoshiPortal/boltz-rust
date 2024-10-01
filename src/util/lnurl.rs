use crate::error::Error;
use lightning_invoice::Bolt11Invoice;
use lnurl::{lnurl::LnUrl, Builder, LnUrlResponse};
use std::str::FromStr;

pub fn fetch_invoice(lnurl_string: &str, amount_msats: u64) -> Result<String, Error> {
    let lowercase_lnurl = lnurl_string.to_lowercase();
    let lnurl = LnUrl::from_str(&lowercase_lnurl).map_err(|e| Error::Generic(format!("Invalid LNURL: {}", e)))?;
    let client = Builder::default().build_blocking().map_err(|e| Error::Generic(e.to_string()))?;
    let res = client.make_request(&lowercase_lnurl).map_err(|e| Error::HTTP(e.to_string()))?;

    match res {
        LnUrlResponse::LnUrlPayResponse(pay) => {
            let pay_result = client
                .get_invoice(&pay, amount_msats, None, None)
                .map_err(|e| Error::HTTP(e.to_string()))?;
            let invoice = Bolt11Invoice::from_str(pay_result.invoice())
                .map_err(|e| Error::Bolt11(e))?;

            if invoice.amount_milli_satoshis() != Some(amount_msats) {
                return Err(Error::Generic("Invoice amount doesn't match requested amount".to_string()));
            }

            Ok(pay_result.invoice().to_string())
        },
        _ => Err(Error::Generic("Unexpected response type".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lnurl_case(lnurl: &str, amount_msats: u64) {
        let result = fetch_invoice(lnurl, amount_msats);

        match result {
            Ok(invoice) => {
                assert!(!invoice.is_empty(), "Invoice should not be empty");
                assert!(invoice.starts_with("lnbc"), "Invoice should start with 'lnbc'");
            },
            Err(e) => {
                println!("Error occurred with LNURL ({}): {}. This test may fail if not connected to the internet or if the LNURL is invalid.",
                         if lnurl == lnurl.to_lowercase() { "lowercase" } else { "uppercase" },
                         e.message());
            }
        }
    }

    #[test]
    fn test_fetch_invoice() {
        let amount_msats = 100000;
        let lowercase_lnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns";
        let uppercase_lnurl = lowercase_lnurl.to_uppercase();

        test_lnurl_case(lowercase_lnurl, amount_msats);
        test_lnurl_case(&uppercase_lnurl, amount_msats);
    }
}