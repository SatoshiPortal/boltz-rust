mod bitcoin;
mod boltz;
mod network;

use ::bitcoin::PublicKey;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use tokio::runtime::Runtime;
use uniffi::deps::anyhow;

uniffi::setup_scaffolding!();
