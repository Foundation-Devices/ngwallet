use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath};
use bdk_wallet::bitcoin::{Network, NetworkKind};
use thiserror::Error;

/// A parsed BIP-0044 like derivation path (single-sig).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NgAccountPath {
    /// The purpose number of the account, usually the BIP number
    /// (e.g. BIP-0044).
    pub purpose: u32,
    /// The coin type, indicates the network on Bitcoin.
    pub coin_type: u32,
    /// The account number.
    pub account: u32,
    /// The script type for BIP-0048 derivation paths.
    pub script_type: Option<u32>,
    /// If equal to one, indicates that this derivation path
    /// is for a change address.
    pub change: Option<u32>,
    /// The address index.
    pub address_index: Option<u32>,
}

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum ParsePathError {
    #[error("expected coin type in the derivation path")]
    ExpectedCoinType,
    #[error("expected account in the derivation path")]
    ExpectedAccount,
    #[error("expected script type in the derivation path")]
    ExpectedScriptType,
    #[error("expected a hardened child number in the derivation path")]
    ExpectedHardened,
    #[error("expected BIP45 cosigner index in the derivation path")]
    ExpectedCosignerIndex,
    #[error("expected BIP45 change index in the derivation path")]
    ExpectedChange,
    #[error("expected BIP45 address index in the derivation path")]
    ExpectedAddressIndex,
    #[error("change index must be zero or one")]
    InvalidChange,
    #[error("BIP45 change index must be zero or one")]
    InvalidBip45Change,
    #[error("derivation path contains an unexpected child number")]
    UnexpectedChild,
}

impl NgAccountPath {
    /// Parse a BIP-0044 like derivation path.
    pub fn parse(path: impl AsRef<[ChildNumber]>) -> Result<Option<Self>, ParsePathError> {
        let mut iter = path.as_ref().iter().copied();

        // Only proceed if purpose is a BIP purpose we know, otherwise just
        // return early.
        let Ok(Some(purpose)) = Self::expect_hardened(&mut iter) else {
            return Ok(None);
        };

        if !matches!(purpose, 44 | 48 | 49 | 84 | 86) {
            return Ok(None);
        }

        // At this point we know the purpose so we expect these fields and
        // they should be correct.
        let coin_type =
            Self::expect_hardened(&mut iter)?.ok_or(ParsePathError::ExpectedCoinType)?;
        let account = Self::expect_hardened(&mut iter)?.ok_or(ParsePathError::ExpectedAccount)?;

        let script_type = if purpose == 48 {
            Some(Self::expect_hardened(&mut iter)?.ok_or(ParsePathError::ExpectedScriptType)?)
        } else {
            None
        };

        // Change and address index are optional, but should still be valid.
        let change = Self::expect_normal(&mut iter)?;
        if let Some(change) = change
            && !matches!(change, 0 | 1)
        {
            return Err(ParsePathError::InvalidChange);
        }

        let address_index = if change.is_some() {
            Self::expect_normal(&mut iter)?
        } else {
            None
        };

        if iter.next().is_some() {
            return Err(ParsePathError::UnexpectedChild);
        }

        Ok(Some(Self {
            purpose,
            coin_type,
            account,
            script_type,
            change,
            address_index,
        }))
    }

    fn expect_hardened(
        iter: &mut impl Iterator<Item = ChildNumber>,
    ) -> Result<Option<u32>, ParsePathError> {
        match iter.next() {
            Some(ChildNumber::Hardened { index }) => Ok(Some(index)),
            Some(_) => Err(ParsePathError::ExpectedHardened),
            None => Ok(None),
        }
    }

    fn expect_normal(
        iter: &mut impl Iterator<Item = ChildNumber>,
    ) -> Result<Option<u32>, ParsePathError> {
        match iter.next() {
            Some(ChildNumber::Normal { index }) => Ok(Some(index)),
            Some(_) => Err(ParsePathError::ExpectedHardened),
            None => Ok(None),
        }
    }

    /// Returns true if this derivation is for an address and not only
    /// for an account.
    pub fn is_for_address(&self) -> bool {
        self.change.is_some() && self.address_index.is_some()
    }

    /// Returns true if this derivation path is valid for the purpose and
    /// network fields.
    pub fn matches(&self, purpose: u32, network: Network) -> bool {
        if self.purpose != purpose {
            return false;
        }

        if !self.is_valid_for_network(network).unwrap_or(false) {
            return false;
        }

        true
    }

    /// Returns true if the derivation path is valid for the given network.
    pub fn is_valid_for_network(&self, network: Network) -> Option<bool> {
        self.is_valid_for_network_kind(network.into())
    }

    /// Returns true if the derivation path is valid for the given network kind.
    pub fn is_valid_for_network_kind(&self, network: NetworkKind) -> Option<bool> {
        self.to_network_kind().map(|v| network == v)
    }

    /// Convert this to a [`NetworkKind`], if the coin type is standard.
    pub fn to_network_kind(&self) -> Option<NetworkKind> {
        match self.coin_type {
            0 => Some(NetworkKind::Main),
            1 => Some(NetworkKind::Test),
            _ => None,
        }
    }

    /// Returns `true` if the derivation path is for a change address,
    /// `false` if not or if the address type is unknown (non-standard).
    pub fn is_change(&self) -> Option<bool> {
        self.change.map(|change| change == 1)
    }

    /// Return the type of keychain.
    pub fn keychain_kind(&self) -> Option<KeychainKind> {
        self.is_change().map(|is_change| {
            if is_change {
                KeychainKind::Internal
            } else {
                KeychainKind::External
            }
        })
    }
}

/// A complete BIP45 member derivation path.
///
/// BIP45 deliberately has no coin-type or account level. Its full address
/// paths are `m/45'/cosigner_index/change/address_index`, where every child
/// after the purpose is unhardened and `change` is either zero or one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip45Path {
    /// Position of this member's root key in the lexicographically sorted
    /// BIP45 cosigner set.
    pub cosigner_index: u32,
    /// Zero for receive addresses and one for change addresses.
    pub change: u32,
    /// Address index within the selected keychain.
    pub address_index: u32,
}

impl Bip45Path {
    pub const PURPOSE: u32 = 45;

    /// Parse a complete standard BIP45 address path.
    pub fn parse(path: impl AsRef<[ChildNumber]>) -> Result<Option<Self>, ParsePathError> {
        let mut iter = path.as_ref().iter().copied();

        let Ok(Some(purpose)) = NgAccountPath::expect_hardened(&mut iter) else {
            return Ok(None);
        };
        if purpose != Self::PURPOSE {
            return Ok(None);
        }

        let cosigner_index = NgAccountPath::expect_normal(&mut iter)?
            .ok_or(ParsePathError::ExpectedCosignerIndex)?;
        let change =
            NgAccountPath::expect_normal(&mut iter)?.ok_or(ParsePathError::ExpectedChange)?;
        if !matches!(change, 0 | 1) {
            return Err(ParsePathError::InvalidBip45Change);
        }
        let address_index =
            NgAccountPath::expect_normal(&mut iter)?.ok_or(ParsePathError::ExpectedAddressIndex)?;
        if iter.next().is_some() {
            return Err(ParsePathError::UnexpectedChild);
        }

        Ok(Some(Self {
            cosigner_index,
            change,
            address_index,
        }))
    }

    /// Return the keychain represented by this path.
    pub fn keychain_kind(&self) -> KeychainKind {
        match self.change {
            0 => KeychainKind::External,
            1 => KeychainKind::Internal,
            // `parse` validates this invariant; retain a deterministic result
            // if a caller constructs the public struct manually.
            _ => KeychainKind::External,
        }
    }

    /// Return the member-key origin which a BIP45 multisig descriptor stores.
    pub fn member_derivation(&self) -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::Hardened {
                index: Self::PURPOSE,
            },
            ChildNumber::Normal {
                index: self.cosigner_index,
            },
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::bitcoin::bip32::DerivationPath;
    use std::str::FromStr;

    #[test]
    fn parse_bip84() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(84, Network::Bitcoin));
        assert_eq!(account.is_change(), Some(false));
    }

    #[test]
    fn parse_bip49_change() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0'/1/1").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Bitcoin));
        assert_eq!(account.is_change(), Some(true));
    }

    #[test]
    fn parse_bip49_keychain_kind() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0'/1/1").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Bitcoin));
        assert_eq!(account.keychain_kind(), Some(KeychainKind::Internal));

        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0'/0/1").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Bitcoin));
        assert_eq!(account.keychain_kind(), Some(KeychainKind::External));
    }

    #[test]
    fn parse_bip49_coin_type() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/1'/0'/0/1").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Testnet4));
        assert_eq!(account.is_change(), Some(false));
    }

    #[test]
    fn parse_invalid() {
        // Not complete
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/49'").unwrap()),
            Err(ParsePathError::ExpectedCoinType),
        );
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/49'/0'").unwrap()),
            Err(ParsePathError::ExpectedAccount)
        );

        // Non-hardened child numbers.
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/49/0/0/0/1").unwrap()),
            Ok(None),
        );
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/49'/0/0/0/1").unwrap()),
            Err(ParsePathError::ExpectedHardened)
        );
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0/0/1").unwrap()),
            Err(ParsePathError::ExpectedHardened)
        );

        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/84'/0'/0'/2/0").unwrap()),
            Err(ParsePathError::InvalidChange),
        );
        assert_eq!(
            NgAccountPath::parse(DerivationPath::from_str("m/84'/0'/0'/0/0/1").unwrap()),
            Err(ParsePathError::UnexpectedChild),
        );
    }

    #[test]
    fn matches_purpose() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Bitcoin));
        assert!(!account.matches(84, Network::Bitcoin));
    }

    #[test]
    fn matches_network() {
        let account = NgAccountPath::parse(DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap())
            .unwrap()
            .unwrap();
        assert!(account.matches(49, Network::Bitcoin));
        assert!(!account.matches(49, Network::Testnet4));
    }

    #[test]
    fn parse_bip45_member_path() {
        let path = Bip45Path::parse(DerivationPath::from_str("m/45'/1/0/7").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(path.cosigner_index, 1);
        assert_eq!(path.address_index, 7);
        assert_eq!(path.keychain_kind(), KeychainKind::External);
        assert_eq!(
            path.member_derivation(),
            DerivationPath::from_str("m/45'/1").unwrap()
        );

        let change = Bip45Path::parse(DerivationPath::from_str("m/45'/1/1/7").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(change.keychain_kind(), KeychainKind::Internal);
    }

    #[test]
    fn parse_bip45_rejects_nonstandard_children() {
        assert_eq!(
            Bip45Path::parse(DerivationPath::from_str("m/45'/1/2/7").unwrap()),
            Err(ParsePathError::InvalidBip45Change),
        );
        assert_eq!(
            Bip45Path::parse(DerivationPath::from_str("m/45'/1/0/7/0").unwrap()),
            Err(ParsePathError::UnexpectedChild),
        );
    }
}
