use std::str::FromStr;

use bdk_wallet::bitcoin::{
    Address, AddressType, CompressedPublicKey, Network, PrivateKey, PublicKey,
    bip32::{DerivationPath, Xpriv},
    key::TapTweak,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sign_message::{MessageSignature, signed_msg_hash},
};
use thiserror::Error;

use crate::bip32::NgAccountPath;

/// A signed Bitcoin message.
///
/// The signature scheme depends on the address type:
/// * legacy / SegWit (BIP-44/49/84/48) addresses use BIP-137 (recoverable ECDSA);
/// * Taproot (BIP-86) addresses use BIP-322 (Simple variant, Schnorr).
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

    #[error("BIP-322 signing failed: {0}")]
    Bip322(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("unsupported address type for verification")]
    UnsupportedAddressType,
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

    let signature = if purpose == 86 {
        // Taproot: BIP-137 is undefined for P2TR, so use BIP-322 (Simple
        // variant), which produces a Schnorr signature that verifies against
        // the tweaked output key committed to by the bc1p... address.
        bip322::sign_simple_encoded(&address.to_string(), message, &private_key.to_wif())
            .map_err(|e| SignMessageError::Bip322(e.to_string()))?
    } else {
        // Legacy / SegWit: BIP-137 recoverable ECDSA.
        let msg_hash = signed_msg_hash(message);
        let msg = Message::from_digest_slice(msg_hash.as_ref())?;
        let recoverable = secp.sign_ecdsa_recoverable(&msg, &private_key.inner);
        let message_signature = MessageSignature {
            signature: recoverable,
            compressed: true,
        };
        message_signature.to_base64()
    };

    Ok(SignedMessage {
        message: message.to_string(),
        address: address.to_string(),
        signature,
    })
}

/// Verify a signed Bitcoin message.
///
/// The verification scheme is selected from the address type:
/// * Taproot (P2TR / bc1p...) addresses are verified with BIP-322 (Simple);
/// * legacy and SegWit addresses (P2PKH, P2SH-P2WPKH, P2WPKH) are verified
///   with BIP-137 by recovering the public key from the recoverable ECDSA
///   signature and checking that it matches the address.
///
/// Returns `Ok(false)` for a malformed or non-matching signature, and only
/// `Err(..)` when the address cannot be parsed or its type is unsupported.
pub fn verify_signed_message(
    message: &str,
    address: &str,
    signature: &str,
) -> Result<bool, SignMessageError> {
    let parsed = Address::from_str(address)
        .map_err(|e| SignMessageError::InvalidAddress(e.to_string()))?
        .assume_checked();

    match parsed.address_type() {
        Some(AddressType::P2tr) => {
            // BIP-322 Simple (Schnorr).
            Ok(bip322::verify_simple_encoded(address, message, signature).is_ok())
        }
        Some(AddressType::P2pkh | AddressType::P2sh | AddressType::P2wpkh) => {
            let secp = Secp256k1::new();
            let Ok(message_signature) = MessageSignature::from_base64(signature) else {
                return Ok(false);
            };
            let msg_hash = signed_msg_hash(message);
            let Ok(pubkey) = message_signature.recover_pubkey(&secp, msg_hash) else {
                return Ok(false);
            };
            // `is_related_to_pubkey` matches P2PKH, P2WPKH and P2SH-P2WPKH
            // payloads against the recovered key.
            Ok(parsed.is_related_to_pubkey(&pubkey))
        }
        _ => Err(SignMessageError::UnsupportedAddressType),
    }
}

/// Format a signed message in the standard Bitcoin signed message format.
pub fn format_signed_message(signed: &SignedMessage) -> String {
    format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n{}\n-----BEGIN BITCOIN SIGNATURE-----\n{}\n{}\n-----END BITCOIN SIGNATURE-----",
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

        // The taproot signature must round-trip through BIP-322 verification.
        assert!(
            verify_signed_message(&result.message, &result.address, &result.signature).unwrap(),
            "BIP-322 taproot signature should verify"
        );

        // A different message must not verify against the same signature.
        assert!(
            !verify_signed_message("Goodbye, Bitcoin!", &result.address, &result.signature)
                .unwrap(),
            "signature should not verify for a different message"
        );
    }

    #[test]
    fn verify_round_trip_all_purposes() {
        let seed = test_seed();
        let message = "Hello, Bitcoin!";
        for path in [
            "m/44'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/86'/0'/0'/0/0",
            "m/48'/0'/0'/2'/0/0",
        ] {
            let result = sign_message(&seed, path, message, Network::Bitcoin).unwrap();
            assert!(
                verify_signed_message(&result.message, &result.address, &result.signature).unwrap(),
                "signature for {path} should verify"
            );
            assert!(
                !verify_signed_message("tampered", &result.address, &result.signature).unwrap(),
                "tampered message for {path} should not verify"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_address() {
        let seed = test_seed();
        let signed = sign_message(
            &seed,
            "m/84'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();

        let other = sign_message(
            &seed,
            "m/84'/0'/0'/0/1",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();
        assert_ne!(signed.address, other.address);
        assert!(
            !verify_signed_message(&signed.message, &other.address, &signed.signature).unwrap(),
            "signature should not verify against a different address"
        );
    }

    #[test]
    fn verify_malformed_signature_is_false() {
        let seed = test_seed();
        let signed = sign_message(
            &seed,
            "m/84'/0'/0'/0/0",
            "Hello, Bitcoin!",
            Network::Bitcoin,
        )
        .unwrap();
        assert!(
            !verify_signed_message(&signed.message, &signed.address, "not-a-signature").unwrap()
        );
    }

    #[test]
    fn verify_invalid_address_errors() {
        let result = verify_signed_message("msg", "not-an-address", "sig");
        assert!(matches!(result, Err(SignMessageError::InvalidAddress(_))));
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
        assert!(formatted.contains("-----BEGIN BITCOIN SIGNATURE-----"));
        assert!(formatted.contains("bc1qtest"));
        assert!(formatted.contains("base64sig"));
        assert!(formatted.contains("-----END BITCOIN SIGNATURE-----"));
    }
}
