use std::collections::HashSet;
use std::sync::Arc;
use crate::store::MetaStorage;
use anyhow::Result;
use log::info;
use redb::{AccessGuard, Builder, Database, Error, ReadableTable, StorageBackend, TableDefinition};
use crate::config::NgAccountConfig;

const NOTE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("notes");
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");
const TAGS_LIST: TableDefinition<&str, &str> = TableDefinition::new("tags_list");

const DO_NOT_SPEND_TABLE: TableDefinition<&str, bool> = TableDefinition::new("do_not_spend");

const ACCOUNT_CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");


#[derive(Debug)]
pub struct RedbMetaStorage {
    db: Arc<Database>,
}

impl RedbMetaStorage {
    pub fn new(path: Option<String>, backend: Option<impl StorageBackend>) -> Self {
        let db = {
            match backend {
                None => {
                    let file_path = path.clone().map(|p| format!("{}/wallet.meta", p)).unwrap_or("wallet.meta".to_string());
                    Builder::new().create(file_path).unwrap()
                }
                Some(b) => {
                    Builder::new().create_with_backend(b).unwrap()
                }
            }
        };

        RedbMetaStorage {
            db: Arc::new(db),
        }
    }

    pub fn open(path: Option<String>) -> Self {
        let file_path = path.map(|p| format!("{}/wallet.meta", p)).unwrap_or("wallet.meta".to_string());
        RedbMetaStorage {
            db: Arc::new(Database::open(file_path).unwrap()),
        }
    }


    pub fn persist(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl MetaStorage for RedbMetaStorage {
    fn set_note(&mut self, key: &str, value: &str) -> Result<()> {
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
            Ok(table) => {
                match table.get(key) {
                    Ok(result) => {
                        match result {
                            None => {
                                Ok(Some("".to_string()))
                            }
                            Some(value) => {
                                Ok(Some(value.value().to_string()))
                            }
                        }
                    }
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                }
            }
            Err(error) => {
                Ok(Some("".to_string()))
            }
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
            Err(err) => {
                Err(anyhow::anyhow!(err.to_string()))
            }
        }
    }

    fn add_tag(&mut self, tag: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TAGS_LIST)?;
            table.insert(tag.clone().to_string().to_lowercase().as_str(), tag)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn remove_tag(&mut self, tag: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TAGS_LIST)?;
            table.remove(tag)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn set_tag(&mut self, key: &str, value: &str) -> Result<()> {
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
            Ok(table) => {
                match table.get(key) {
                    Ok(v) => {
                        match v {
                            None => {
                                Ok(Some("".to_string()))
                            }
                            Some(value) => {
                                Ok(Some(value.value().to_string()))
                            }
                        }
                    }
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                }
            }
            Err(err) => {
                Ok(Some("".to_string()))
            }
        }
    }

    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(DO_NOT_SPEND_TABLE)?;
            table.insert(&key, &value)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn get_do_not_spend(&self, key: &str) -> Result<Option<bool>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(DO_NOT_SPEND_TABLE) {
            Ok(table) => {
                match table.get(key) {
                    Ok(v) => {
                        match v {
                            None => {
                                Ok(Some(true))
                            }
                            Some(value) => {
                                Ok(Some(value.value().clone()))
                            }
                        }
                    }
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                }
            }
            Err(_) => {
                Ok(Some(true))
            }
        }
    }

    fn set_config(&mut self, deserialized_config: &str) -> Result<()> {
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
            Ok(table) => {
                match table.get("config") {
                    Ok(v) => {
                        let config: NgAccountConfig = serde_json::from_str(v.unwrap().value()).unwrap();
                        Ok(Some(config))
                    }
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                }
            }
            Err(_) => {
                Ok(None)
            }
        }
    }

    fn persist(&mut self) -> Result<bool> {
        return Ok(true);
    }
}
