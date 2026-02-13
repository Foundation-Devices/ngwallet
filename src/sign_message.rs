use std::str::FromStr;

use bdk_wallet::bitcoin::{
    Address, CompressedPublicKey, Network, PrivateKey, PublicKey,
    bip32::{DerivationPath, Xpriv},
    key::TapTweak,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sign_message::{MessageSignature, signed_msg_hash},
};
use thiserror::Error;

use crate::bip32::NgAccountPath;

/// A signed Bitcoin message (BIP-137).
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The original message that was signed.
    pub message: String,
    /// The address used for signing.
    pub address: String,
    /// The base64-encoded signature.
    pub signature: String,
}

#[derive(Debug, Error)]
pub enum SignMessageError {
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] bdk_wallet::bitcoin::bip32::Error),

    #[error("unsupported derivation path format")]
    UnsupportedDerivationPath,

    #[error("derivation path must include change and address index")]
    IncompleteDerivationPath,

    #[error("unsupported purpose: {0}")]
    UnsupportedPurpose(u32),

    #[error("failed to compress public key")]
    CompressPublicKey,

    #[error("invalid message digest: {0}")]
    InvalidDigest(#[from] bdk_wallet::bitcoin::secp256k1::Error),
}

/// Sign a Bitcoin message using BIP-137.
///
/// The `seed` should be a 64-byte raw seed (e.g. from `Mnemonic::to_seed`).
/// The `derivation_path` must be a full path including change and address index
/// (e.g. `"m/84'/0'/0'/0/0"`).
pub fn sign_message(
    seed: &[u8],
    derivation_path: &str,
    message: &str,
    network: Network,
) -> Result<SignedMessage, SignMessageError> {
    let secp = Secp256k1::new();

    let path = DerivationPath::from_str(derivation_path)?;

    let account_path = NgAccountPath::parse(&path)
        .map_err(|_| SignMessageError::UnsupportedDerivationPath)?
        .ok_or(SignMessageError::UnsupportedDerivationPath)?;

    if !account_path.is_for_address() {
        return Err(SignMessageError::IncompleteDerivationPath);
    }

    let purpose = account_path.purpose;
    if !matches!(purpose, 44 | 48 | 49 | 84 | 86) {
        return Err(SignMessageError::UnsupportedPurpose(purpose));
    }

    let xpriv = Xpriv::new_master(network, seed)?.derive_priv(&secp, &path)?;

    let private_key = PrivateKey::new(xpriv.private_key, network);
    let public_key = private_key.public_key(&secp);
    let compressed_pubkey = CompressedPublicKey::try_from(public_key)
        .map_err(|_| SignMessageError::CompressPublicKey)?;

    let address =
        derive_address_from_purpose(purpose, &compressed_pubkey, &public_key, network, &secp)?;

    let msg_hash = signed_msg_hash(message);
    let msg = Message::from_digest_slice(msg_hash.as_ref())?;
    let signature = secp.sign_ecdsa_recoverable(&msg, &private_key.inner);

    let message_signature = MessageSignature {
        signature,
        compressed: true,
    };
    let sig_base64 = message_signature.to_base64();

    Ok(SignedMessage {
        message: message.to_string(),
        address: address.to_string(),
        signature: sig_base64,
    })
}

/// Format a signed message in the standard Bitcoin signed message format.
pub fn format_signed_message(signed: &SignedMessage) -> String {
    format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n{}\n-----BEGIN SIGNATURE-----\n{}\n{}\n-----END BITCOIN SIGNED MESSAGE-----",
        signed.message, signed.address, signed.signature
    )
}

fn derive_address_from_purpose(
    purpose: u32,
    compressed_pubkey: &CompressedPublicKey,
    public_key: &PublicKey,
    network: Network,
    secp: &Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
) -> Result<Address, SignMessageError> {
    match purpose {
        44 | 48 => Ok(Address::p2pkh(public_key, network)),
        49 => Ok(Address::p2shwpkh(compressed_pubkey, network)),
        84 => Ok(Address::p2wpkh(compressed_pubkey, network)),
        86 => {
            let x_only_pubkey = XOnlyPublicKey::from(public_key.inner);
            let (tweaked_key, _parity) = x_only_pubkey.tap_tweak(secp, None);
            Ok(Address::p2tr_tweaked(tweaked_key, network))
        }
        _ => Err(SignMessageError::UnsupportedPurpose(purpose)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::keys::bip39::Mnemonic;

    const TEST_MNEMONIC: &str =
        "axis minimum please frozen option smooth alone identify term fatigue crisp entry";

    fn test_seed() -> Vec<u8> {
        Mnemonic::parse(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
    }

    #[test]
    fn sign_bip84() {
        let seed = test_seed();
        let result = sign_message(
            &seed,
            "m/84'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(result.address, "bc1qm6aw3ek0jvsngylhu3rnw66wv9g67ukah2lenl");
        assert!(!result.signature.is_empty());
        assert_eq!(result.message, "Hello, Bitcoin!");
    }

    #[test]
    fn sign_bip44() {
        let seed = test_seed();
        let result = sign_message(
            &seed,
            "m/44'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(result.address, "1Fm18EiVn4He6y1omPa4AXPXuvmiR7VuCS");
        assert!(!result.signature.is_empty());
    }

    #[test]
    fn sign_bip49() {
        let seed = test_seed();
        let result = sign_message(
            &seed,
            "m/49'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        assert_eq!(result.address, "39ruEa1n8zde66saXTcCV9kx1wgbokFotR");
        assert!(!result.signature.is_empty());
    }

    #[test]
    fn sign_bip86() {
        let seed = test_seed();
        let result = sign_message(
            &seed,
            "m/86'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        assert!(!result.signature.is_empty());
        assert!(result.address.starts_with("bc1p"));
    }

    #[test]
    fn sign_bip48() {
        let seed = test_seed();
        let result = sign_message(
            &seed,
            "m/48'/0'/0'/2'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        assert!(!result.signature.is_empty());
    }

    #[test]
    fn invalid_derivation_path() {
        let seed = test_seed();
        let result = sign_message(&seed, "invalid", "test", Network::Bitcoin);
        assert!(result.is_err());
    }

    #[test]
    fn incomplete_derivation_path() {
        let seed = test_seed();
        let result = sign_message(&seed, "m/84'/0'/0'", "test", Network::Bitcoin);
        assert!(matches!(
            result,
            Err(SignMessageError::IncompleteDerivationPath)
        ));
    }

    #[test]
    fn unsupported_purpose() {
        let seed = test_seed();
        // Purpose 99 is not a recognized BIP purpose, NgAccountPath::parse returns None
        let result = sign_message(&seed, "m/99'/0'/0'/0/0", "test", Network::Bitcoin);
        assert!(matches!(
            result,
            Err(SignMessageError::UnsupportedDerivationPath)
        ));
    }

    #[test]
    fn format_signed_message_output() {
        let signed = SignedMessage {
            message: "test message".to_string(),
            address: "bc1qtest".to_string(),
            signature: "base64sig".to_string(),
        };
        let formatted = format_signed_message(&signed);
        assert!(formatted.contains("-----BEGIN BITCOIN SIGNED MESSAGE-----"));
        assert!(formatted.contains("test message"));
        assert!(formatted.contains("-----BEGIN SIGNATURE-----"));
        assert!(formatted.contains("bc1qtest"));
        assert!(formatted.contains("base64sig"));
        assert!(formatted.contains("-----END BITCOIN SIGNED MESSAGE-----"));
    }
}
