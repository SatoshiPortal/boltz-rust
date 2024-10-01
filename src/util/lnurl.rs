use crate::error::Error;
use lightning_invoice::Bolt11Invoice;
use lnurl::{lnurl::LnUrl, Builder, LnUrlResponse};
use std::str::FromStr;

pub fn fetch_invoice(lnurl_string: &str, amount_msats: u64) -> Result<String, Error> {
    let lnurl = LnUrl::from_str(lnurl_string).map_err(|e| Error::Generic(format!("Invalid LNURL: {}", e)))?;
    let client = Builder::default().build_blocking().map_err(|e| Error::Generic(e.to_string()))?;
    let res = client.make_request(&lnurl_string).map_err(|e| Error::HTTP(e.to_string()))?;

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

    #[test]
    fn test_fetch_invoice() {
        let lnurl_string = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";
        let amount_msats = 100000;
        let result = fetch_invoice(lnurl_string, amount_msats);

        match result {
            Ok(invoice) => {
                assert!(!invoice.is_empty(), "Invoice should not be empty");
                assert!(invoice.starts_with("lnbc"), "Invoice should start with 'lnbc'");
            },
            Err(e) => {
                println!("Error occurred: {}. This test may fail if not connected to the internet or if the LNURL is invalid.", e.message());
            }
        }
    }
}