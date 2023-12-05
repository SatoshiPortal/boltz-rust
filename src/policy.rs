use crate::config::WalletConfig;
use crate::e::{ErrorKind, S5Error};
use bdk::database::MemoryDatabase;
// use bdk::descriptor::policy::{Policy, Satisfaction, SatisfiableItem};
use bdk::descriptor::{Descriptor, Legacy, Miniscript, Segwitv0};
use bdk::miniscript::policy::Concrete;
use bdk::KeychainKind;
use bdk::Wallet;
use serde::{Deserialize, Serialize};
// use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::os::raw::c_char;
use std::str::FromStr;

/// FFI Output
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletPolicy {
    pub policy: String,
    pub descriptor: String,
}
impl WalletPolicy {
    pub fn _c_stringify(&self) -> *mut c_char {
        let stringified = match serde_json::to_string(self) {
            Ok(result) => result,
            Err(_) => {
                return CString::new("Error:JSON Stringify Failed. BAD NEWS! Contact Support.")
                    .unwrap()
                    .into_raw()
            }
        };

        CString::new(stringified).unwrap().into_raw()
    }
}

pub enum ScriptType {
    WPKH,
    WSH,
    SHWSH,
    SH,
    TR,
}
impl Display for ScriptType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ScriptType::WPKH => write!(f, "wpkh"),
            ScriptType::WSH => write!(f, "wsh"),
            ScriptType::SHWSH => write!(f, "sh-wsh"),
            ScriptType::SH => write!(f, "sh"),
            ScriptType::TR => write!(f, "tr"),
        }
    }
}

impl ScriptType {
    pub fn from_str(script_str: &str) -> ScriptType {
        match script_str {
            "wpkh" => ScriptType::WPKH,
            "wsh" => ScriptType::WSH,
            "sh-wsh" => ScriptType::SHWSH,
            "sh" => ScriptType::SH,
            "tr" => ScriptType::TR,
            _ => ScriptType::WPKH,
        }
    }
}
pub fn compile(policy: &str, script_type: ScriptType) -> Result<String, S5Error> {
    let x_policy = match Concrete::<String>::from_str(policy) {
        Ok(result) => result,
        Err(_) => return Err(S5Error::new(ErrorKind::Input, "Invalid Policy")),
    };
    let legacy_policy: Miniscript<String, Legacy> = match x_policy.compile() {
        Ok(result) => result,
        Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
    };
    let segwit_policy: Miniscript<String, Segwitv0> = match x_policy.compile() {
        Ok(result) => result,
        Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
    };
    let descriptor = match script_type {
        ScriptType::WPKH => policy.replace("pk(", "wpkh("),
        ScriptType::SH => Descriptor::new_sh(legacy_policy).unwrap().to_string(),
        ScriptType::WSH => Descriptor::new_wsh(segwit_policy).unwrap().to_string(),
        ScriptType::SHWSH => Descriptor::new_sh_wsh(segwit_policy).unwrap().to_string(),
        ScriptType::TR => policy.replace("pk(", "tr("),
    };
    Ok(descriptor.split('#').collect::<Vec<&str>>()[0].to_string())
}

// pub fn _decode(config: WalletConfig) -> Result<Policy, S5Error> {
//   let wallet = match Wallet::new_offline(
//     &config.deposit_desc,
//     Some(&config.change_desc),
//     config.network,
//     MemoryDatabase::default(),
//   ) {
//     Ok(result) => result,
//     Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
//   };

//   let external_policies = wallet.policies(KeychainKind::External).unwrap().unwrap();
//   println!("{:#?}", external_policies);
//   println!(
//     "The policy with id {} requires the following conditions to be satisfied.",
//     external_policies.id
//   );

//   match external_policies.clone().satisfaction {
//     Satisfaction::Partial {
//       n,
//       m,
//       items,
//       sorted,
//       conditions,
//     } => {
//       println!("{}/{} conditions need to be satisfied.", m, n);
//     }
//     Satisfaction::PartialComplete {
//       n,
//       m,
//       items,
//       sorted,
//       conditions,
//     } => {
//       println!("{}/{} conditions need to be satisfied.", m, n);
//     }
//     Satisfaction::Complete { condition } => {
//       println!("{:#?} conditions need to be satisfied.", condition);
//     }
//     _ => {
//       println!("No conditions need to be satisfied :o Free coinsh??");
//     }
//   };

//   let mut path = BTreeMap::new();
//   path.insert(external_policies.item.id(), vec![0]);
//   let conditions = external_policies.get_condition(&path);
//   println!("is_leaf: {:#?}", external_policies.item.is_leaf());

//   match &external_policies.item {

//     SatisfiableItem::Thresh { items, threshold } => {
//       for item in items {
//         match &item.item {
//           SatisfiableItem::Signature(pkorf) => {
//             println!("is_leaf: {:#?}", item.item.is_leaf());
//             println!("{:#?}, id: {:#?}", format!("{:?}", pkorf), item.item.id());
//           }
//           SatisfiableItem::Thresh { items, threshold } => {
//             for item in items {
//               match &item.item {
//                 SatisfiableItem::Signature(pkorf) => {
//                   println!("is_leaf: {:#?}", item.item.is_leaf());
//                   println!("{:#?}, id: {:#?}", format!("{:?}", pkorf), item.item.id());
//                 }
//                 _ => {
//                   println!("NOT A SIGNATURE POLICY: {:#?}", item.item.id());
//                 }
//               }
//             }
//           }
//           _ => {
//             println!("NOT A SIGNATURE POLICY: {:#?}", item.item.id());
//           }
//         }
//       }
//     }
//     SatisfiableItem::Multisig { keys, threshold } => {
//     }
//     SatisfiableItem::AbsoluteTimelock { value } => {}
//     SatisfiableItem::RelativeTimelock { value } => {}
//     _ => {}
//   };
//   Ok(external_policies)
// }

/// Checks wether a wallet needs to specify policy path and returns the root policy node id.
pub fn id(config: WalletConfig) -> Result<(bool, String), S5Error> {
    let wallet = match Wallet::new(
        &config.deposit_desc,
        Some(&config.change_desc),
        config.network,
        MemoryDatabase::default(),
    ) {
        Ok(result) => result,
        Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
    };

    let external_policies = wallet.policies(KeychainKind::External).unwrap().unwrap();
    Ok((external_policies.requires_path(), external_policies.id))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{WalletConfig, DEFAULT_TESTNET_NODE};
    use crate::address::generate;
    // use bdk::descriptor::policy::BuildSatisfaction;
    // use bdk::descriptor::ExtractPolicy;
    // use bitcoin::secp256k1::Secp256k1;
    // use std::sync::Arc;
    #[test]
    fn test_policies() {
        let alice_xprv = "[db7d25b5/84'/1'/6']tprv8fWev2sCuSkVWYoNUUSEuqLkmmfiZaVtgxosS5jRE9fw5ejL2odsajv1QyiLrPri3ppgyta6dsFaoDVCF4ZdEAR6qqY4tnaosujsPzLxB49/*";
        let escrow_xpub = "[66a0c105/84'/1'/5']tpubDCKvnVh6U56wTSUEJGamQzdb3ByAc6gTPbjxXQqts5Bf1dBMopknipUUSmAV3UuihKPTddruSZCiqhyiYyhFWhz62SAGuC3PYmtAafUuG6R/*";
        let bob_xprv = "[a90a3a81/84'/0'/0']tprv8g3FKkLE9gRHDYeedikuNRXMhZyQ6bsgnMxYk8dRPKg15BCsimrbw2zjA97gwu4Brw9XtVVdgyuUSSZd7ckjSbbwpGjAyVjonCXGKg2gE2D/*";
        let bailout_time = 595_600;
        // POLICIES
        let single_policy = format!("pk({})", alice_xprv);
        let raft_policy = format!(
            "or(pk({}),and(pk({}),after({})))",
            alice_xprv, escrow_xpub, bailout_time
        );
        let escrow_policy = format!(
            "thresh(2,pk({}),pk({}),pk({}))",
            alice_xprv, bob_xprv, escrow_xpub
        );
        //  DESCRIPTORS
        let raft_result_bech32 = compile(&raft_policy, ScriptType::WSH).unwrap();
        let expected_raft_wsh = "wsh(or_d(pk([db7d25b5/84'/1'/6']tprv8fWev2sCuSkVWYoNUUSEuqLkmmfiZaVtgxosS5jRE9fw5ejL2odsajv1QyiLrPri3ppgyta6dsFaoDVCF4ZdEAR6qqY4tnaosujsPzLxB49/*),and_v(v:pk([66a0c105/84'/1'/5']tpubDCKvnVh6U56wTSUEJGamQzdb3ByAc6gTPbjxXQqts5Bf1dBMopknipUUSmAV3UuihKPTddruSZCiqhyiYyhFWhz62SAGuC3PYmtAafUuG6R/*),after(595600))))";
        let single_result_bech32 = compile(&single_policy, ScriptType::WPKH).unwrap();
        let expected_single_wpkh = "wpkh([db7d25b5/84'/1'/6']tprv8fWev2sCuSkVWYoNUUSEuqLkmmfiZaVtgxosS5jRE9fw5ejL2odsajv1QyiLrPri3ppgyta6dsFaoDVCF4ZdEAR6qqY4tnaosujsPzLxB49/*)";

        let escrow_result = compile(&escrow_policy, ScriptType::WSH).unwrap();
        let expected_escrow_wsh = "wsh(multi(2,[db7d25b5/84'/1'/6']tprv8fWev2sCuSkVWYoNUUSEuqLkmmfiZaVtgxosS5jRE9fw5ejL2odsajv1QyiLrPri3ppgyta6dsFaoDVCF4ZdEAR6qqY4tnaosujsPzLxB49/*,[a90a3a81/84'/0'/0']tprv8g3FKkLE9gRHDYeedikuNRXMhZyQ6bsgnMxYk8dRPKg15BCsimrbw2zjA97gwu4Brw9XtVVdgyuUSSZd7ckjSbbwpGjAyVjonCXGKg2gE2D/*,[66a0c105/84'/1'/5']tpubDCKvnVh6U56wTSUEJGamQzdb3ByAc6gTPbjxXQqts5Bf1dBMopknipUUSmAV3UuihKPTddruSZCiqhyiYyhFWhz62SAGuC3PYmtAafUuG6R/*))";
        assert_eq!(&raft_result_bech32, expected_raft_wsh);
        assert_eq!(&single_result_bech32, expected_single_wpkh);
        assert_eq!(&escrow_result, expected_escrow_wsh);

        let raft_config: WalletConfig =
            WalletConfig::new(&raft_result_bech32, DEFAULT_TESTNET_NODE, None,None).unwrap();
        let escrow_config: WalletConfig =
            WalletConfig::new(&escrow_result, DEFAULT_TESTNET_NODE, None,None).unwrap();

        let raft_id = id(raft_config).unwrap();
        let expected_raft_id = "hgl9rs6e";
        let escrow_id = id(escrow_config).unwrap();
        let expected_escrow_id = "s4wk2rav";
        assert_eq!(raft_id.1, expected_raft_id);
        assert_eq!(escrow_id.1, expected_escrow_id);
        assert!(raft_id.0);
        assert!(!escrow_id.0);
    }

    #[test]
    fn test_taproot_policy() {
        let hash = "".to_string();
        let mykey = "".to_string();
        let boltzkey = "".to_string();
        let timeout = "".to_string();
        let swap_policy_example = format!("or(and(hash160({}), pk({}), and(pk({}), after({})",hash,mykey,boltzkey,timeout);        
    }
     
}