use crate::config::{AddressType, NgAccountConfig};
use crate::store::MetaStorage;
use anyhow::{Context, Result};
use bdk_wallet::KeychainKind;
use redb::{Builder, Database, ReadableTable, TableDefinition, TableError};

const FEE_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fees");

const NOTE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("notes");
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");
const TAGS_LIST: TableDefinition<&str, &str> = TableDefinition::new("tags_list");

const DO_NOT_SPEND_TABLE: TableDefinition<&str, bool> = TableDefinition::new("do_not_spend");

const ACCOUNT_CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");

const LAST_VERIFIED_ADDRESS_TABLE: TableDefinition<&str, u32> =
    TableDefinition::new("last_verified_address");

const SCHEMA_TABLE: TableDefinition<&str, u32> = TableDefinition::new("schema");
const SCHEMA_VERSION_KEY: &str = "version";
/// Bump when the table layout changes, and migrate older versions in `initialize`.
const SCHEMA_VERSION: u32 = 1;

/// Opens every metadata table in `$txn`. A write transaction creates the
/// missing ones; in a read transaction a missing or retyped table is an error.
macro_rules! open_all_tables {
    ($txn:expr) => {{
        $txn.open_table(FEE_TABLE)?;
        $txn.open_table(NOTE_TABLE)?;
        $txn.open_table(TAG_TABLE)?;
        $txn.open_table(TAGS_LIST)?;
        $txn.open_table(DO_NOT_SPEND_TABLE)?;
        $txn.open_table(ACCOUNT_CONFIG)?;
        $txn.open_table(LAST_VERIFIED_ADDRESS_TABLE)?;
    }};
}

#[derive(Debug)]
pub struct RedbMetaStorage {
    db: Database,
}

impl RedbMetaStorage {
    pub fn from_file(path: Option<String>) -> anyhow::Result<Self> {
        let db = {
            let file_path = path
                .clone()
                .map(|p| format!("{p}/account.meta"))
                .unwrap_or("account.meta".to_string());
            Builder::new()
                .create(file_path)
                .with_context(|| "Failed to create redb database")?
        };

        Self::from_db(db)
    }

    pub fn from_db(db: Database) -> anyhow::Result<Self> {
        initialize(&db).with_context(|| "Account metadata is damaged or unsupported")?;
        Ok(Self { db })
    }
}

/// Creates every table up front and records the schema version, so a table that
/// is missing later means the file was damaged, not that it was never written.
///
/// Files written before the version was recorded have no marker. They get their
/// missing tables created once; anything they lost before that can't be detected.
fn initialize(db: &Database) -> Result<()> {
    let version = {
        let read_txn = db.begin_read()?;
        match read_txn.open_table(SCHEMA_TABLE) {
            Ok(table) => table.get(SCHEMA_VERSION_KEY)?.map(|v| v.value()),
            Err(TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        }
    };

    match version {
        Some(SCHEMA_VERSION) => {
            let read_txn = db.begin_read()?;
            open_all_tables!(read_txn);
        }
        Some(other) => anyhow::bail!("unsupported metadata schema version {other}"),
        None => {
            let write_txn = db.begin_write()?;
            open_all_tables!(write_txn);
            write_txn
                .open_table(SCHEMA_TABLE)?
                .insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION)?;
            write_txn.commit()?;
        }
    }

    Ok(())
}

// Every table exists once `initialize` has run, so the getters below treat a
// table that can't be opened as an error rather than as "no data".
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
        let table = read_txn.open_table(FEE_TABLE)?;
        Ok(table.get(txid)?.map(|value| value.value()))
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
        let table = read_txn.open_table(NOTE_TABLE)?;
        let note = table.get(key)?.map(|value| value.value().to_string());
        Ok(Some(note.unwrap_or_default()))
    }

    fn list_tags(&self) -> Result<Vec<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TAGS_LIST)?;
        let mut items: Vec<String> = vec![];
        for item in table.iter()? {
            let (_, tag) = item?;
            items.push(tag.value().to_string())
        }
        Ok(items)
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
        let table = read_txn.open_table(TAG_TABLE)?;
        let tag = table.get(key)?.map(|value| value.value().to_string());
        Ok(Some(tag.unwrap_or_default()))
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
        let table = read_txn.open_table(DO_NOT_SPEND_TABLE)?;
        Ok(table.get(key)?.is_some_and(|value| value.value()))
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
        let table = read_txn.open_table(ACCOUNT_CONFIG)?;
        match table.get("config")? {
            Some(value) => serde_json::from_str(value.value())
                .map(Some)
                .with_context(|| "Failed to parse account config"),
            None => Ok(None),
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
        let table = read_txn.open_table(LAST_VERIFIED_ADDRESS_TABLE)?;
        let key = format!("{},{}", address_type as u8, keychain as u8);
        Ok(table.get(key.as_str())?.map_or(0, |value| value.value()))
    }

    // Each write above commits its own transaction, so there is nothing left to flush.
    fn persist(&self) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::backends::InMemoryBackend;

    fn memory_db() -> Database {
        Builder::new()
            .create_with_backend(InMemoryBackend::new())
            .unwrap()
    }

    fn schema_version(db: &Database) -> Option<u32> {
        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(SCHEMA_TABLE).unwrap();
        table.get(SCHEMA_VERSION_KEY).unwrap().map(|v| v.value())
    }

    fn delete_do_not_spend_table(db: &Database) {
        let write_txn = db.begin_write().unwrap();
        assert!(write_txn.delete_table(DO_NOT_SPEND_TABLE).unwrap());
        write_txn.commit().unwrap();
    }

    #[test]
    fn new_database_has_every_table_and_no_data() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();

        assert_eq!(schema_version(&storage.db), Some(SCHEMA_VERSION));
        assert!(!storage.get_do_not_spend("txid:0").unwrap());
        assert_eq!(storage.get_fee("txid").unwrap(), None);
        assert_eq!(storage.get_note("txid").unwrap(), Some(String::new()));
        assert_eq!(storage.get_tag("txid:0").unwrap(), Some(String::new()));
        assert!(storage.list_tags().unwrap().is_empty());
        assert!(storage.get_config().unwrap().is_none());
        assert_eq!(
            storage
                .get_last_verified_address(AddressType::P2wpkh, KeychainKind::External)
                .unwrap(),
            0
        );
    }

    #[test]
    fn unversioned_database_is_migrated_and_keeps_its_data() {
        let db = memory_db();
        {
            // Written before the schema was versioned: only the tables that were used.
            let write_txn = db.begin_write().unwrap();
            write_txn
                .open_table(DO_NOT_SPEND_TABLE)
                .unwrap()
                .insert("txid:0", true)
                .unwrap();
            write_txn.commit().unwrap();
        }

        let storage = RedbMetaStorage::from_db(db).unwrap();

        assert_eq!(schema_version(&storage.db), Some(SCHEMA_VERSION));
        assert!(storage.get_do_not_spend("txid:0").unwrap());
        assert!(storage.list_tags().unwrap().is_empty());
    }

    #[test]
    fn lock_survives_reopening() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();
        storage.set_do_not_spend("txid:0", true).unwrap();

        let reopened = RedbMetaStorage::from_db(storage.db).unwrap();

        assert!(reopened.get_do_not_spend("txid:0").unwrap());
        assert!(!reopened.get_do_not_spend("txid:1").unwrap());
    }

    #[test]
    fn missing_lock_table_fails_to_open() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();
        storage.set_do_not_spend("txid:0", true).unwrap();
        delete_do_not_spend_table(&storage.db);

        let error = RedbMetaStorage::from_db(storage.db).unwrap_err();

        assert!(format!("{error:?}").contains("do_not_spend"), "{error:?}");
    }

    #[test]
    fn missing_lock_table_is_an_error_not_unlocked() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();
        storage.set_do_not_spend("txid:0", true).unwrap();
        delete_do_not_spend_table(&storage.db);

        assert!(storage.get_do_not_spend("txid:0").is_err());
    }

    #[test]
    fn unsupported_schema_version_fails_to_open() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();
        {
            let write_txn = storage.db.begin_write().unwrap();
            write_txn
                .open_table(SCHEMA_TABLE)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION + 1)
                .unwrap();
            write_txn.commit().unwrap();
        }

        assert!(RedbMetaStorage::from_db(storage.db).is_err());
    }

    #[test]
    fn unreadable_config_is_an_error() {
        let storage = RedbMetaStorage::from_db(memory_db()).unwrap();
        storage.set_config("not json").unwrap();

        assert!(storage.get_config().is_err());
    }
}
