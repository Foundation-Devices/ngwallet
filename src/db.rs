use crate::config::{AddressType, NgAccountConfig};
use crate::store::MetaStorage;
use anyhow::{Context, Result};
use bdk_wallet::KeychainKind;
use redb::{Builder, Database, ReadableTable, StorageBackend, TableDefinition};
use std::sync::Arc;

const NOTE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("notes");
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");
const TAGS_LIST: TableDefinition<&str, &str> = TableDefinition::new("tags_list");

const DO_NOT_SPEND_TABLE: TableDefinition<&str, bool> = TableDefinition::new("do_not_spend");

const ACCOUNT_CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");

const LAST_VERIFIED_ADDRESS_TABLE: TableDefinition<&str, u32> =
    TableDefinition::new("last_verified_address");

#[derive(Debug)]
pub struct RedbMetaStorage {
    db: Arc<Database>,
}

impl RedbMetaStorage {
    pub fn from_file(path: Option<String>) -> anyhow::Result<Self> {
        let db = {
            let file_path = path
                .clone()
                .map(|p| format!("{}/account.meta", p))
                .unwrap_or("account.meta".to_string());
            Builder::new()
                .create(file_path)
                .with_context(|| "Failed to create database")?
        };

        Ok(RedbMetaStorage { db: Arc::new(db) })
    }

    pub fn from_backend(backend: impl StorageBackend) -> anyhow::Result<Self> {
        let db = Builder::new()
            .create_with_backend(backend)
            .with_context(|| "Failed to create database")?;
        Ok(RedbMetaStorage { db: Arc::new(db) })
    }

    //TODO: fix persist
    #[allow(dead_code)]
    pub fn persist(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl MetaStorage for RedbMetaStorage {
    fn set_note(&self, key: &str, value: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(NOTE_TABLE)?;
            table.insert(&key, &value)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn get_note(&self, key: &str) -> Result<Option<String>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(NOTE_TABLE) {
            Ok(table) => match table.get(key) {
                Ok(result) => match result {
                    None => Ok(Some("".to_string())),
                    Some(value) => Ok(Some(value.value().to_string())),
                },
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            },
            Err(_error) => Ok(Some("".to_string())),
        }
    }

    fn list_tags(&self) -> Result<Vec<String>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(TAGS_LIST) {
            Ok(table) => {
                let table_iter = table.iter().unwrap();
                let mut items: Vec<String> = vec![];
                for item in table_iter {
                    let a = item.unwrap();
                    items.push(a.1.value().to_string())
                }
                Ok(items)
            }
            Err(err) => Err(anyhow::anyhow!(err.to_string())),
        }
    }

    fn add_tag(&self, tag: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TAGS_LIST)?;
            table.insert(tag.to_string().to_lowercase().as_str(), tag)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn remove_tag(&self, tag: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TAGS_LIST)?;
            table.remove(tag)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn set_tag(&self, key: &str, value: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TAG_TABLE)?;
            table.insert(&key, &value)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn get_tag(&self, key: &str) -> Result<Option<String>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(TAG_TABLE) {
            Ok(table) => match table.get(key) {
                Ok(v) => match v {
                    None => Ok(Some("".to_string())),
                    Some(value) => Ok(Some(value.value().to_string())),
                },
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            },
            Err(_) => Ok(Some("".to_string())),
        }
    }

    fn set_do_not_spend(&self, key: &str, value: bool) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(DO_NOT_SPEND_TABLE)?;
            table.insert(&key, &value)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn get_do_not_spend(&self, key: &str) -> Result<bool> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(DO_NOT_SPEND_TABLE) {
            Ok(table) => match table.get(key) {
                Ok(v) => match v {
                    None => Ok(false),
                    Some(value) => Ok(value.value()),
                },
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            },
            Err(_) => Ok(false),
        }
    }

    fn set_config(&self, deserialized_config: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ACCOUNT_CONFIG)?;
            table.insert("config", deserialized_config)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn get_config(&self) -> Result<Option<NgAccountConfig>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(ACCOUNT_CONFIG) {
            Ok(table) => match table.get("config") {
                Ok(v) => {
                    let config: NgAccountConfig = serde_json::from_str(v.unwrap().value()).unwrap();
                    Ok(Some(config))
                }
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            },
            Err(_) => Ok(None),
        }
    }

    fn set_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(LAST_VERIFIED_ADDRESS_TABLE)?;
            table.insert(
                format!("{},{}", address_type as u8, keychain as u8).as_str(),
                index,
            )?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn get_last_verified_address(
        &self,
        address_type: AddressType,
        keychain: KeychainKind,
    ) -> Result<u32> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(LAST_VERIFIED_ADDRESS_TABLE) {
            Ok(table) => {
                match table.get(format!("{},{}", address_type as u8, keychain as u8).as_str()) {
                    Ok(v) => match v {
                        None => Ok(0),
                        Some(value) => Ok(value.value()),
                    },
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                }
            }
            Err(_) => Ok(0),
        }
    }

    fn persist(&self) -> Result<bool> {
        Ok(true)
    }
}
