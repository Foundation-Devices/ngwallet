use {
    super::{Error, Result},
    bdk_wallet::bitcoin::{
        Psbt,
        bip32::Xpriv,
        secp256k1::{All, Secp256k1},
    },
};

pub fn sign(psbt: &mut Psbt, master: &Xpriv, secp: &Secp256k1<All>, expected: usize) -> Result<()> {
    if expected == 0 {
        return Err(Error::Sign("no device signatures were expected".into()));
    }
    let fingerprint = master.fingerprint(secp);
    let before = count_signatures(psbt, fingerprint);
    let _ = psbt.sign(master, secp);
    let added = count_signatures(psbt, fingerprint).saturating_sub(before);
    if added < expected {
        return Err(Error::Sign(format!(
            "device produced {added} of {expected} expected signatures"
        )));
    }
    Ok(())
}

fn count_signatures(psbt: &Psbt, fingerprint: bdk_wallet::bitcoin::bip32::Fingerprint) -> usize {
    psbt.inputs
        .iter()
        .map(|input| {
            input
                .partial_sigs
                .keys()
                .filter(|public_key| {
                    input
                        .bip32_derivation
                        .get(&public_key.inner)
                        .is_some_and(|(candidate, _)| *candidate == fingerprint)
                })
                .count()
        })
        .sum()
}
