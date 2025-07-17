use crate::config::{AddressType, NgAccountConfig};
use anyhow::Result;
use bdk_wallet::KeychainKind;
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

pub trait MetaStorage: Debug + Send + Sync {
    fn set_note(&self, key: &str, value: &str) -> Result<()>;
    fn get_note(&self, key: &str) -> Result<Option<String>>;

    fn list_tags(&self) -> Result<Vec<String>>;
    fn add_tag(&self, tag: &str) -> Result<()>;
    fn remove_tag(&self, tag: &str) -> Result<()>;
    fn set_tag(&self, key: &str, value: &str) -> Result<()>;
    fn get_tag(&self, key: &str) -> Result<Option<String>>;

    fn set_do_not_spend(&self, key: &str, value: bool) -> Result<()>;
    fn get_do_not_spend(&self, key: &str) -> Result<bool>;

    fn set_config(&self, deserialized_config: &str) -> Result<()>;
    fn get_config(&self) -> Result<Option<NgAccountConfig>>;

    fn set_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<()>;
    fn get_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
    ) -> Result<u32>;

    fn persist(&self) -> Result<bool>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryMetaStorage {
    config_store: Map<String, String>,
    notes_store: Map<String, String>,
    tag_store: Map<String, String>,
    tag_list: Map<String, String>,
    do_not_spend_store: Map<String, bool>,
    last_verified_address_store: Map<(AddressType, KeychainKind), u32>,
}

type Map<K, V> = Arc<Mutex<std::collections::HashMap<K, V>>>;

impl MetaStorage for InMemoryMetaStorage {
    fn set_note(&self, key: &str, value: &str) -> Result<()> {
        self.notes_store
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn get_note(&self, key: &str) -> Result<Option<String>> {
        let map = self.notes_store.lock().unwrap();
        Ok(map.get(key).cloned())
    }

    fn list_tags(&self) -> Result<Vec<String>> {
        let map = self.tag_list.lock().unwrap();
        Ok(map.keys().cloned().collect())
    }

    fn add_tag(&self, tag: &str) -> Result<()> {
        let mut map = self.tag_list.lock().unwrap();
        map.insert(tag.to_lowercase().to_string(), tag.to_string());
        Ok(())
    }

    fn remove_tag(&self, tag: &str) -> Result<()> {
        let mut map = self.tag_list.lock().unwrap();
        map.remove(tag);
        Ok(())
    }

    fn set_tag(&self, key: &str, value: &str) -> Result<()> {
        let mut map = self.tag_store.lock().unwrap();
        map.insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn get_tag(&self, key: &str) -> Result<Option<String>> {
        let map = self.tag_store.lock().unwrap();
        Ok(map.get(key).cloned())
    }
    fn set_do_not_spend(&self, key: &str, value: bool) -> Result<()> {
        let mut map = self.do_not_spend_store.lock().unwrap();
        map.insert(key.to_string(), value);
        Ok(())
    }
    fn get_do_not_spend(&self, key: &str) -> Result<bool> {
        let map = self.do_not_spend_store.lock().unwrap();
        Ok(map.get(key).cloned().unwrap_or(false))
    }

    fn set_config(&self, deserialized_config: &str) -> Result<()> {
        let mut map = self.config_store.lock().unwrap();
        map.insert("config".to_string(), deserialized_config.to_string());
        Ok(())
    }
    fn get_config(&self) -> Result<Option<NgAccountConfig>> {
        let map = self.config_store.lock().unwrap();
        let config_str = map.get("config");
        if let Some(config_str) = config_str {
            let config: NgAccountConfig = serde_json::from_str(config_str)?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    fn set_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<()> {
        let mut map = self.last_verified_address_store.lock().unwrap();
        map.insert((address_type, keychain), index);
        Ok(())
    }

    fn get_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
    ) -> Result<u32> {
        let map = self.last_verified_address_store.lock().unwrap();
        Ok(map.get(&(address_type, keychain)).unwrap_or(&0).to_owned())
    }

    fn persist(&self) -> Result<bool> {
        // In-memory storage does not require persistence
        Ok(true)
    }
}
