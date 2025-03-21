use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::InMemoryMetaStorage;


#[derive(Debug)]
pub struct NgAccount {
    pub name: String,
    pub color: String,
    pub device_serial: Option<String>,
    pub index: u32,
    pub wallet: NgWallet,
}

impl NgAccount {
    pub fn new_from_descriptor(
        name: String,
        color: String,
        device_serial: Option<String>,
        descriptor: String,
        index: u32,
        db_path: Option<String>,
    ) -> Self {
        let wallet =
            NgWallet::new_from_descriptor(db_path, descriptor, Box::new(RedbMetaStorage::new()))
                .unwrap();
        Self {
            name,
            color,
            device_serial,
            index,
            wallet,
        }
    }

    pub fn new(name: String, color: String, device_serial: Option<String>, index: u32) -> Self {
        let wallet = NgWallet::new(None, Box::new(RedbMetaStorage::new())).unwrap();
        Self {
            name,
            color,
            device_serial,
            index,
            wallet,
        }
    }

    pub fn get_backup(&self) -> Vec<u8> {


        vec![]
    }

    pub fn restore_backup(&mut self, backup: Vec<u8>) {
    }
}
