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

#[cfg(test)]
mod tests {
    use super::parse_bolt12_invoice;

    #[test]
    fn test_parse_bolt12_invoice_example_1() {
        let invoice_str = "lni1qqg0ec390prlx7twmetwtsutqlkjkq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy83vggzcncmzqua57ytd2r5l00ka7n599v57rctrwqa5rpn57gqhvgrxph4qgqxyfhyvyg6pdvu4tcjvpp7kkal9rp57wj7xv4pl3ajku70rzy3pafq8xyksp2qqkppqfyczd00f00puf4x6leqj8fpsg57yk70vp2mjqhtea4x0e8rwuf9egycqtz0rvgrnknc3d4gwnaa7mh6ws54jnc0pvdcrksvxwneqza3qvcx7q5rtnnrrl78j37an98k7ffqpr5x2ha9mdwgmqt62269cqpdwqkv2cqs92fuq9z94zjpztk5phdr8cvh6669ca344fgzlrwza6v9tuuedls3qqezmqareeuj86qssuck00fxs4ysrmzzj2fy6qjkquxpavnjnmntxzf6ptxkv54e6r9f65q526cnxnpnk056y8qqqqqqqqqqqqqqqysqqqqqqqqqqqqp6f9jm7k9yqqqqqq2gprfegm0l2pqtxd3nlg5qgcax3mu7n4xjassnt5sy6yhvthctf8duvh5gsw0muu65qucj6q2uqczqqqtqggzcncmzqua57ytd2r5l00ka7n599v57rctrwqa5rpn57gqhvgrxphlqsyn7q548cgapx4z4x9sjfr2fmz9mqtgsqrnyjwl6fzfdgls3tu97w29jcnfedyvzfqm8qlr5g279a0xep6w3w67y0we8kk83kzwrvhtw";

        let invoice = parse_bolt12_invoice(invoice_str).unwrap();

        assert_eq!(
            invoice.payment_hash().to_string(),
            "599b19fd140231d3477cf4ea6976109ae902689762ef85a4ede32f4441cfdf39"
        );
        assert_eq!(invoice.amount_msats(), 10_000_000);
    }

    #[test]
    fn test_parse_bolt12_invoice_example_2() {
        let invoice_str = "lni1qqg99wlxfjy9xt6fqae765px3an7vzsqzrhq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0qgw9suh47dqt052gn4sznndrfjpe0u23895kf6sawlyaep5hpnxp5qszjlapxvh7xp6lxnmt66yzyucchmsjkn2t3dgxvldvy94zf8rxplfqqvcc633sg8spja2d7xaqwjymxxaa2fzxwzk6wlu6jtqjfnkdgwraxtct7z95nng5rn83elaae6352smcj3tyqdmagvuj8xrtzlkgegxnh8gkzk4lrpm4yvxztncx8g4t7e8chgl7vqpj7dagt698qxnfwunqqx5zzrjjpygn809dp48m7tnvnsfk88qesfjejegp6d28flc75ar5z22vq3yg5r092gpsmrxq2sq9sggrj8927agtlmqlp0wqq3g0a9n86tkd0v79e96v09rhqypev9u4llt2plgpvgpcvnhsyh77376c0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrcrvheggdr20rhf3njfjvk26x0jscgnun2nm2ayar2647zk6yy82k9qyq6zkcxa55yqx79akzku0u82e85e3r2qfg54gmrdk6dg87y4z30v4qqyt6acldfnw3azw6ykskffzp7ngsuq3nqf89v288uxrxaad7uuxuk87gvt36ga3hwyt3uxe7tu62n43cwwzh6d234f4xuuj5d8558g2w4vakhd8zuqy08cc9wrlvysmd4q0dlr8d2c5uedds7hxz4qlfu64mnrsdm9tq2aqz2fm2zf0npju4vvzvtm8hujdl7pjycu377sp9vqluvrw3z85l6vz8el74npwudhtz2frtqw5uyczw75juxfjrr4y0j74ew0yw2u50q364hh3zuza3ed9l36l940rdk83rtrxnwaz84j0x3yemtvaued2u5glatxp0km7d6jm0ky58t26mew73t9egly4q34fh9yldhlypwa9kx27pf9d7xnwhdj6wp6em3nm4ajlnkcad025gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqrvvcqqqq5szxnj3hhwnqxq23sz5zqzs2h6gaty8fkx3vvnp2sdnhlrlsnc2h8696zr37veaw5p4kt9664gpsmrxq4cpsyqqqkqssxa75xwfrnp430myv5rfmn5tpt2l3sa6jxrp9eurr524lvnut50lx7pqqn286x7t92kumtpd02ycv5nsalz6gfx0zqyc0d6jsu6ytvvt4l6ua9evzr8fqksc023v9ypjd98zwc22f2gmsad4e4m2mrjv9yv34lu";

        let invoice = parse_bolt12_invoice(invoice_str).unwrap();

        assert_eq!(
            invoice.payment_hash().to_string(),
            "0a0abe91d590e9b1a2c64c2a83677f8ff09e1573e8ba10e3e667aea06b65975a"
        );
        assert_eq!(invoice.amount_msats(), 888_000);
    }
}
