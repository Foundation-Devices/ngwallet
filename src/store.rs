use anyhow::Result;
use std::fmt::{Debug, Formatter};

pub trait MetaStorage: Debug + Send + Sync {
    fn set_note(&mut self, key: &str, value: &str) -> Result<()>;
    fn get_note(&self, key: &str) -> Result<Option<String>>;

    fn set_tag(&mut self, key: &str, value: String) -> Result<()>;
    fn get_tag(&self, key: &str) -> Option<String>;

    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()>;
    fn get_do_not_spend(&self, key: &str) -> Option<bool>;
}

pub struct InMemoryMetaStorage {
    notes_store: std::collections::HashMap<String, String>,
    tag_store: std::collections::HashMap<String, String>,
    do_not_spend_store: std::collections::HashMap<String, bool>,
}

impl InMemoryMetaStorage {
    pub fn new() -> Self {
        InMemoryMetaStorage {
            notes_store: std::collections::HashMap::new(),
            tag_store: std::collections::HashMap::new(),
            do_not_spend_store: std::collections::HashMap::new(),
        }
    }
}

impl MetaStorage for InMemoryMetaStorage {
    fn set_note(&mut self, key: &str, value: &str) -> Result<()> {
        self.notes_store.insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn get_note(&self, key: &str) -> Result<Option<String>> {
        Ok(self.notes_store.get(key).cloned())
    }
    fn set_tag(&mut self, key: &str, value: String) -> Result<()> {
        self.tag_store.insert(key.to_string(), value);
        Ok(())
    }
    fn get_tag(&self, key: &str) -> Option<String> {
        self.tag_store.get(key).cloned()
    }
    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()> {
        self.do_not_spend_store.insert(key.to_string(), value);
        Ok(())
    }
    fn get_do_not_spend(&self, key: &str) -> Option<bool> {
        self.do_not_spend_store.get(key).cloned()
    }
}

impl Debug for InMemoryMetaStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryMetaStorage")
            .field("notes_store", &self.notes_store)
            .field("tag_store", &self.tag_store)
            .field("do_not_spend_store", &self.do_not_spend_store)
            .finish()
    }
}
