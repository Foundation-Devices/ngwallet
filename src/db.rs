use crate::config::{AddressType, NgAccountConfig};
use crate::store::MetaStorage;
use anyhow::{Context, Result};
use bdk_wallet::KeychainKind;
use redb::{
    Builder, Database, Key, ReadTransaction, ReadableTable, TableDefinition, TableError,
    TableHandle, Value, WriteTransaction,
};

const FEE_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fees");

const NOTE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("notes");
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");
const TAGS_LIST: TableDefinition<&str, &str> = TableDefinition::new("tags_list");

const DO_NOT_SPEND_TABLE: TableDefinition<&str, bool> = TableDefinition::new("do_not_spend");

const ACCOUNT_CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");

const LAST_VERIFIED_ADDRESS_TABLE: TableDefinition<&str, u32> =
    TableDefinition::new("last_verified_address");

#[derive(Debug)]
pub struct RedbMetaStorage {
    db: Database,
}

impl RedbMetaStorage {
    pub fn from_file(path: Option<String>) -> anyhow::Result<Self> {
        let db = {
            let file_path = meta_file_path(path);
            Builder::new()
                .create(file_path)
                .with_context(|| "Failed to create redb database")?
        };

        Ok(RedbMetaStorage { db })
    }

    pub fn from_db(db: Database) -> Self {
        Self { db }
    }

    //TODO: fix persist
    #[allow(dead_code)]
    pub fn persist(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    /// Moves the metadata in `path` to a fresh file, with `config` as the
    /// account config. Updating a value in place leaves the old bytes in pages
    /// redb has freed but not yet reused; a fresh file holds only live data.
    pub(crate) fn rewrite_file(path: Option<String>, config: &str) -> Result<()> {
        let file_path = meta_file_path(path);
        let new_path = format!("{file_path}.new");
        // A leftover from an interrupted rewrite holds nothing the live file lacks.
        let _ = std::fs::remove_file(&new_path);
        {
            let old = Database::open(&file_path)?;
            let read_txn = old.begin_read()?;
            // Only these tables are copied, so refuse rather than drop another.
            let known = [
                FEE_TABLE.name().to_string(),
                NOTE_TABLE.name().to_string(),
                TAG_TABLE.name().to_string(),
                TAGS_LIST.name().to_string(),
                DO_NOT_SPEND_TABLE.name().to_string(),
                ACCOUNT_CONFIG.name().to_string(),
                LAST_VERIFIED_ADDRESS_TABLE.name().to_string(),
            ];
            if let Some(table) = read_txn
                .list_tables()?
                .find(|table| !known.iter().any(|name| name == table.name()))
            {
                anyhow::bail!("Unknown metadata table {}", table.name());
            }
            if read_txn.list_multimap_tables()?.next().is_some() {
                anyhow::bail!("Unexpected multimap metadata table");
            }

            let new = Builder::new().create(&new_path)?;
            let write_txn = new.begin_write()?;
            copy_table(&read_txn, &write_txn, FEE_TABLE)?;
            copy_table(&read_txn, &write_txn, NOTE_TABLE)?;
            copy_table(&read_txn, &write_txn, TAG_TABLE)?;
            copy_table(&read_txn, &write_txn, TAGS_LIST)?;
            copy_table(&read_txn, &write_txn, DO_NOT_SPEND_TABLE)?;
            copy_table(&read_txn, &write_txn, LAST_VERIFIED_ADDRESS_TABLE)?;
            write_txn
                .open_table(ACCOUNT_CONFIG)?
                .insert("config", config)?;
            write_txn.commit()?;
        }
        std::fs::rename(&new_path, &file_path)?;
        Ok(())
    }
}

fn meta_file_path(path: Option<String>) -> String {
    path.map(|p| format!("{p}/account.meta"))
        .unwrap_or("account.meta".to_string())
}

/// Copies every entry of `table`, if it exists, from `from` into `to`.
fn copy_table<K: Key + 'static, V: Value + 'static>(
    from: &ReadTransaction,
    to: &WriteTransaction,
    table: TableDefinition<K, V>,
) -> Result<()> {
    let source = match from.open_table(table) {
        Ok(source) => source,
        Err(TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut target = to.open_table(table)?;
    for entry in source.iter()? {
        let (key, value) = entry?;
        target.insert(key.value(), value.value())?;
    }
    Ok(())
}

impl MetaStorage for RedbMetaStorage {
    fn set_fee(&self, txid: &str, fee: u64) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(FEE_TABLE)?;
            table.insert(txid, fee)?;
        }
        write_txn
            .commit()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn get_fee(&self, txid: &str) -> Result<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(FEE_TABLE) {
            Ok(table) => match table.get(txid) {
                Ok(Some(value)) => Ok(Some(value.value())),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            },
            Err(_) => Ok(None),
        }
    }

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
            //keys are stored in lowercase
            table.remove(tag.to_string().to_lowercase().as_str())?;
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
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
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
