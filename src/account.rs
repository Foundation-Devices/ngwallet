use crate::ngwallet::NgWallet;
use crate::store::InMemoryMetaStorage;

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
    ) -> Self {
        let wallet =
            NgWallet::new_from_descriptor(None, descriptor, Box::new(InMemoryMetaStorage::new()))
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
        let wallet = NgWallet::new(None, Box::new(InMemoryMetaStorage::new())).unwrap();
        Self {
            name,
            color,
            device_serial,
            index,
            wallet,
        }
    }
}
