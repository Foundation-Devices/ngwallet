use crate::bip32::{NgAccountPath, ParsePathError};
use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::bip32::{DerivationPath, KeySource};
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can happen during PSBT validation.
#[derive(Debug, Clone, Error)]
pub enum Error {
    /// The network of the PSBT couldn't be determined because more than one
    /// network was used in xpubs or derivation paths.
    #[error("the Bitcoin network used in the PSBT is not consistent")]
    NetworkInconsistency,

    /// A standard derivation path is invalid.
    #[error("the derivation path ({error}) in the PSBT does not conform to standard: {error}")]
    InvalidDerivationPath {
        path: DerivationPath,
        error: ParsePathError,
    },
}

impl Error {
    fn invalid_path(path: DerivationPath, error: ParsePathError) -> Self {
        Self::InvalidDerivationPath { path, error }
    }
}

/// Validate the network of a PSBT.
pub fn validate_network(psbt: &Psbt) -> Result<Option<NetworkKind>, Error> {
    let mut maybe_network =
        psbt.xpub
            .iter()
            .try_fold(None, |mut maybe_network, (xpub, source)| {
                let network = *maybe_network.get_or_insert(xpub.network);
                if network != xpub.network {
                    return Err(Error::NetworkInconsistency);
                }

                // In case we have a BIP-0044 like path validate that coin type
                // and the Xpub network kind match.
                let maybe_path = NgAccountPath::parse(&source.1)
                    .map_err(|e| Error::invalid_path(source.1.clone(), e))?;
                if let Some(path) = maybe_path {
                    // Only return an error if coin type is a standard one.
                    if let Some(false) = path.is_valid_for_network_kind(xpub.network) {
                        return Err(Error::NetworkInconsistency);
                    }
                }

                Ok(Some(network))
            })?;

    // We can only determine the network from the path if it is
    // account-like as here we only have public keys instead of xpubs.
    for input in psbt.inputs.iter() {
        maybe_network = validate_paths_network(&input.bip32_derivation, maybe_network)?;
    }

    for output in psbt.outputs.iter() {
        maybe_network = validate_paths_network(&output.bip32_derivation, maybe_network)?;
    }

    Ok(maybe_network)
}

fn validate_paths_network(
    bip32_derivation: &BTreeMap<PublicKey, KeySource>,
    maybe_network: Option<NetworkKind>,
) -> Result<Option<NetworkKind>, Error> {
    bip32_derivation
        .iter()
        .try_fold(maybe_network, |mut maybe_network, (_public_key, source)| {
            let maybe_path = NgAccountPath::parse(&source.1)
                .map_err(|e| Error::invalid_path(source.1.clone(), e))?;

            let Some(path) = maybe_path else {
                return Ok(maybe_network);
            };

            if let Some(network_kind) = path.to_network_kind() {
                // Highly unlikely that maybe_network is not set already, but
                // do so if there weren't any global xpubs.
                let network = *maybe_network.get_or_insert(network_kind);

                if let Some(false) = path.is_valid_for_network_kind(network) {
                    return Err(Error::NetworkInconsistency);
                }
            }

            Ok(maybe_network)
        })
}
