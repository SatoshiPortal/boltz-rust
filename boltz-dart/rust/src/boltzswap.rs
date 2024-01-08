use boltz_client::swaps::boltz::SwapType;

pub enum BoltzSwapType {
    Submarine,
    Reverse,
}

impl Into<SwapType> for BoltzSwapType {
    fn into(self) -> SwapType {
        match self {
            BoltzSwapType::Submarine => SwapType::Submarine,
            BoltzSwapType::Reverse => SwapType::Reverse,
        }
    }
}
