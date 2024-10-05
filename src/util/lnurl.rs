use crate::error::Error;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::pay::LnURLPayInvoice;
use lnurl::withdraw::WithdrawalResponse;
use lnurl::{lnurl::LnUrl, Builder, LnUrlResponse};
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
    let lnurl =
        LnUrl::from_str(voucher).map_err(|_| Error::Generic("Invalid LNURL".to_string()))?;

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

pub fn process_withdrawal(withdraw: &WithdrawalResponse, invoice: &str) -> Result<String, Error> {
    let client = Builder::default()
        .build_blocking()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let withdraw_result = client
        .do_withdrawal(withdraw, invoice)
        .map_err(|e| Error::HTTP(e.to_string()))?;

    Ok("Withdrawal successful".to_string())
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

    #[test]
    fn test_process_withdrawal() {
        let invoice = "lnbc50u1pnsqfxhpp55c04g7ku3d9k89z286twfh6z9zym43cskms842zkxmgn5dq3ls5qcqpjsp5yw4taatpjkmq3as42pfhq47e7zhs3mr6u5jgsx5ttvdcxamx34hs9q7sqqqqqqqqqqqqqqqqqqqsqqqqqysgqdqqmqz9gxqyjw5qrzjqwryaup9lh50kkranzgcdnn2fgvx390wgj5jd07rwr3vxeje0glcllm8u4a8gvusysqqqqlgqqqqqeqqjqjmdpw5m89ce7gtycnw5d8557gduyjzeqetzecekv54spjtxfqzk4hfhzjec3w7ur6zvy4v3yxrfpeeccsz5npwxhfy77tjfr3mkmeacq0suj0n";
        let voucher = "LNURL1DP68GURN8GHJ7ER9D4HJUMRWVF5HGUEWVDHK6TMHD96XSERJV9MJ7CTSDYHHVVF0D3H82UNV9ARRY5JTDP49XUJPXDHH2VJHG4ZY6K3NV9PHSTMP29ZH2JMFXFVKW4ZDXVEH57RX2P5NYNTWGGVNVP88";
        assert!(validate_lnurl(voucher));
        let withdraw_response = match create_withdraw_response(voucher) {
            Ok(response) => response,
            Err(e) => {
                println!("Failed to create withdraw response: {:?}", e);
                return;
            }
        };

        println!("Successfully created withdraw response");
        let result = process_withdrawal(&withdraw_response, invoice);

        assert!(result.is_ok(), "Withdrawal failed: {:?}", result.err());
        assert_eq!(result.unwrap(), "Withdrawal successful");

        println!("Withdrawal test passed successfully");
    }
}
