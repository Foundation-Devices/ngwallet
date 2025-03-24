use crate::store::MetaStorage;
use anyhow::Result;
use redb::{Database, Error, TableDefinition};

const NOTE_TABLE: TableDefinition<&str, &str> = TableDefinition::new("notes");
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");
const DO_NOT_SPEND_TABLE: TableDefinition<&str, bool> = TableDefinition::new("do_not_spend");

#[derive(Debug)]
pub struct RedbMetaStorage {
    db: Database,
}

impl RedbMetaStorage {
    pub fn new(path: Option<String>) -> Self {
        let file_path = path.unwrap_or("wallet.meta".to_string());
        RedbMetaStorage {
            db: Database::create(file_path).unwrap(),
        }
    }

    pub fn persist(&self) -> Result<Vec<u8>> {
        // read the file and return it here
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
        let table = read_txn.open_table(NOTE_TABLE)?;
        match table.get(key) {
            Ok(v) => Ok(Some(v.unwrap().value().to_string())),
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        }
    }

    fn set_tag(&mut self, key: &str, value: String) -> Result<()> {
        todo!()
    }

    fn get_tag(&self, key: &str) -> Option<String> {
        todo!()
    }

    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()> {
        todo!()
    }

    fn get_do_not_spend(&self, key: &str) -> Option<bool> {
        todo!()
    }
}
