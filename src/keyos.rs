use bdk_wallet::{ChangeSet, WalletPersister};

pub struct KeyOsPersister {

}

impl WalletPersister for KeyOsPersister {
    type Error = ();

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        Ok(ChangeSet::default())
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        Ok(())
    }
}