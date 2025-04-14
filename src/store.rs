use crate::config::NgAccountConfig;
use anyhow::{Result, anyhow};
use std::fmt::{Debug, Formatter};

pub trait MetaStorage: Debug + Send + Sync {
    fn set_note(&mut self, key: &str, value: &str) -> Result<()>;
    fn get_note(&self, key: &str) -> Result<Option<String>>;

    fn list_tags(&self) -> Result<Vec<String>>;
    fn add_tag(&mut self, tag: &str) -> Result<()>;
    fn remove_tag(&mut self, tag: &str) -> Result<()>;
    fn set_tag(&mut self, key: &str, value: &str) -> Result<()>;
    fn get_tag(&self, key: &str) -> Result<Option<String>>;

    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()>;
    fn get_do_not_spend(&self, key: &str) -> Result<bool>;

    fn set_config(&mut self, deserialized_config: &str) -> Result<()>;
    fn get_config(&self) -> Result<Option<NgAccountConfig>>;

    fn persist(&mut self) -> Result<bool>;
}

#[derive(Clone)]
pub struct InMemoryMetaStorage {
    config_store: std::collections::HashMap<String, String>,
    notes_store: std::collections::HashMap<String, String>,
    tag_store: std::collections::HashMap<String, String>,
    tag_list: std::collections::HashSet<String>,
    do_not_spend_store: std::collections::HashMap<String, bool>,
}

impl InMemoryMetaStorage {
    #![allow(dead_code)]
    pub fn new() -> Self {
        InMemoryMetaStorage {
            config_store: std::collections::HashMap::new(),
            notes_store: std::collections::HashMap::new(),
            tag_store: std::collections::HashMap::new(),
            tag_list: std::collections::HashSet::new(),
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

    fn list_tags(&self) -> Result<Vec<String>> {
        Ok(self.tag_list.clone().into_iter().collect())
    }

    fn add_tag(&mut self, tag: &str) -> Result<()> {
        self.tag_list.insert(tag.to_string());
        Ok(())
    }

    fn remove_tag(&mut self, tag: &str) -> Result<()> {
        match self.tag_list.remove(tag) {
            true => Ok(()),
            false => Err(anyhow!("error")),
        }
    }

    fn set_tag(&mut self, key: &str, value: &str) -> Result<()> {
        self.tag_store.insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn get_tag(&self, key: &str) -> Result<Option<String>> {
        Ok(self.tag_store.get(key).cloned())
    }
    fn set_do_not_spend(&mut self, key: &str, value: bool) -> Result<()> {
        self.do_not_spend_store.insert(key.to_string(), value);
        Ok(())
    }
    fn get_do_not_spend(&self, key: &str) -> Result<bool> {
        match self.do_not_spend_store.get(key) {
            None => Ok(false),
            Some(&value) => Ok(value),
        }
    }

    fn set_config(&mut self, deserialized_config: &str) -> Result<()> {
        self.config_store
            .insert("config".to_string(), deserialized_config.to_string());
        Ok(())
    }
    fn get_config(&self) -> Result<Option<NgAccountConfig>> {
        if let Some(config_str) = self.config_store.get("config") {
            let config: NgAccountConfig = serde_json::from_str(config_str)?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    fn persist(&mut self) -> Result<bool> {
        // In-memory storage does not require persistence
        Ok(true)
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
