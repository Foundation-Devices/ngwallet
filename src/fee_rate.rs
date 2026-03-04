use bdk_wallet::bitcoin::FeeRate;
use serde::{Deserialize, Serialize};
use std::ops::Add;

/// Type-safe sat/kvB wrapper for the external API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FeeRateSatPerKvb(pub u64);

/// Type-safe sat/kwu wrapper for internal BDK calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRateSatPerKwu(pub u64);

impl FeeRateSatPerKvb {
    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn from_bdk(fee_rate: FeeRate) -> Self {
        FeeRateSatPerKvb::from(FeeRateSatPerKwu::from_bdk(fee_rate))
    }

    pub fn to_bdk(self) -> FeeRate {
        FeeRateSatPerKwu::from(self).to_bdk()
    }
}

impl FeeRateSatPerKwu {
    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        FeeRateSatPerKwu(sat_per_vb * 250)
    }

    pub fn from_bdk(fee_rate: FeeRate) -> Self {
        FeeRateSatPerKwu(fee_rate.to_sat_per_kwu())
    }

    pub fn to_bdk(self) -> FeeRate {
        FeeRate::from_sat_per_kwu(self.0.max(1))
    }
}

impl From<FeeRateSatPerKvb> for FeeRateSatPerKwu {
    fn from(fee_rate: FeeRateSatPerKvb) -> Self {
        FeeRateSatPerKwu(fee_rate.0 / 4) // 1 sat/kvB = 0.25 sat/kwu
    }
}

impl From<FeeRateSatPerKwu> for FeeRateSatPerKvb {
    fn from(fee_rate: FeeRateSatPerKwu) -> Self {
        FeeRateSatPerKvb(fee_rate.0 * 4) // 1 sat/kwu = 4 sat/kvB
    }
}

impl Add for FeeRateSatPerKwu {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FeeRateSatPerKwu(self.0 + rhs.0)
    }
}
