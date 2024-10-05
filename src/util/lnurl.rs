use crate::error::Error;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::pay::LnURLPayInvoice;
use lnurl::withdraw::WithdrawalResponse;
use lnurl::{lnurl::LnUrl, Builder, LnUrlResponse};
use std::cmp::max;
use std::str::FromStr;

pub fn validate_lnurl(string: &str) -> bool {
    let string = string.to_lowercase();
    match LnUrl::from_str(&string) {
        Ok(lnurl) => true,
        Err(_) => match LightningAddress::from_str(&string) {
            Ok(lightning_address) => true,
            Err(_) => false,
        },
    }
}

pub fn fetch_invoice(address: &str, amount_msats: u64) -> Result<String, Error> {
    let address = address.to_lowercase();
    let lnurl = match LnUrl::from_str(&address) {
        Ok(lnurl) => lnurl,
        Err(_) => match LightningAddress::from_str(&address) {
            Ok(lightning_address) => lightning_address.lnurl(),
            Err(_) => return Err(Error::Generic("Not a valid LnUrl or LnAddress".to_string())),
        },
    };

    let client = Builder::default()
        .build_blocking()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let res = client
        .make_request(&lnurl.url)
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

pub fn create_withdraw_response(voucher: &str) -> Result<WithdrawalResponse, Error> {
    let lnurl = LnUrl::from_str(&*voucher.to_lowercase())
        .map_err(|_| Error::Generic("Invalid LNURL".to_string()))?;

    let client = Builder::default()
        .build_blocking()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let res = client
        .make_request(&lnurl.url)
        .map_err(|e| Error::HTTP(e.to_string()))?;

    match res {
        LnUrlResponse::LnUrlWithdrawResponse(withdraw) => Ok(withdraw),
        _ => Err(Error::Generic("Unexpected response type".to_string())),
    }
}

pub fn process_withdrawal(withdraw: &WithdrawalResponse, invoice: &str) -> Result<(), Error> {
    let client = Builder::default()
        .build_blocking()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let withdraw_result = client
        .do_withdrawal(withdraw, invoice)
        .map_err(|e| Error::HTTP(e.to_string()))?;

    Ok(())
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
        assert!(validate_lnurl(lnurl));
        test_address(lnurl, amount_msats, "LNURL");
        test_address(&uppercase_lnurl, amount_msats, "LNURL");

        let email_lnurl = "drunksteel17@walletofsatoshi.com";
        assert!(validate_lnurl(email_lnurl));
        test_address(email_lnurl, amount_msats, "Lightning Address");
    }

    #[ignore = "Requires using an new lnurl-w voucher and invoice to match the max_withdrawble amount"]
    #[test]
    fn test_process_withdrawal() {
        let invoice = "lnbc5m1pnszpmwpp5vdu4qrghzq4c3uzvll0d82aa8vw2xtywukwgq5jncwwk7av7rdcscqpjsp5pav6wyrk0zaqc6gyfr4048qmnfj7h7ydpul5ds4dmqj4xam679zq9q7sqqqqqqqqqqqqqqqqqqqsqqqqqysgqdqqmqz9gxqyjw5qrzjqwryaup9lh50kkranzgcdnn2fgvx390wgj5jd07rwr3vxeje0glcllm8u4a8gvusysqqqqlgqqqqqeqqjq6g9v7ejekz6uxqqmjjuaaa2s63nzx3d4n9pu8m6h68nmh7rgprky4pn5qae9878q5wpg72p66djy7ywsa7v4mfecdmnyj38etln394cqqzhnzt";
        let voucher = "LNURL1DP68GURN8GHJ7ER9D4HJUMRWVF5HGUEWVDHK6TMHD96XSERJV9MJ7CTSDYHHVVF0D3H82UNV9AZXY56N89F5CDFJW34K63N2GEJXK5N2VD2K6TMRWARKJVN8D565WCNNDFT85WR42FP5GUN2VSDZTX2W";
        assert!(validate_lnurl(voucher));
        let withdraw_response = match create_withdraw_response(voucher) {
            Ok(response) => response,
            Err(e) => {
                println!("Failed to create withdraw response: {:?}", e);
                return;
            }
        };

        let invoice_amount = match Bolt11Invoice::from_str(invoice) {
            Ok(invoice) => invoice.amount_milli_satoshis().unwrap() / 1000,
            Err(e) => {
                println!("Failed to parse invoice: {:?}", e);
                return;
            }
        };

        assert!(
            invoice_amount <= withdraw_response.max_withdrawable,
            "Invoice of {} exceeds max withdrawable {} sats",
            invoice_amount,
            withdraw_response.max_withdrawable
        );
        println!("Successfully created withdraw response");
        let result = process_withdrawal(&withdraw_response, invoice);

        assert!(result.is_ok(), "Withdrawal failed: {:?}", result.err());

        println!("Withdrawal test passed successfully");
    }
}
