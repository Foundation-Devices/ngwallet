use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpub};
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::descriptor::{DerivPaths, DescriptorMultiXKey, Wildcard};
use std::collections::BTreeMap;

/// Returns the descriptor for a P2WSH multisig account.
///
/// The `required_signers` parameter must be known before hand, by for
/// example, disassembling the multisig script.
pub fn multisig_descriptor(
    required_signers: u8,
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> ExtendedDescriptor {
    // Find the account Xpubs in the global Xpub map of the PSBT.
    let xpubs = bip32_derivations
        .iter()
        .map(|(_, (subpath_fingerprint, subpath))| {
            global_xpubs
                .iter()
                .find(|(_, (global_fingerprint, global_path))| {
                    subpath_fingerprint == global_fingerprint
                        && subpath.as_ref().starts_with(global_path.as_ref())
                })
        });

    let mut descriptor_pubkeys = Vec::new();
    for maybe_xpub in xpubs {
        let (xpub, source) = maybe_xpub.unwrap();

        let descriptor_pubkey = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some(source.clone()),
            xkey: *xpub,
            derivation_paths: DerivPaths::new(vec![
                DerivationPath::from(vec![ChildNumber::Normal { index: 0 }]),
                DerivationPath::from(vec![ChildNumber::Normal { index: 1 }]),
            ])
            .expect("the vector passed should not be empty"),
            wildcard: Wildcard::Unhardened,
        });
        descriptor_pubkeys.push(descriptor_pubkey);
    }

    ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), descriptor_pubkeys)
        .unwrap()
}
