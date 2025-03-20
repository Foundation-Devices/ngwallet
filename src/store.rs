use std::fmt::{Debug, Formatter};

pub trait MetaStorage: Debug + Send + Sync {
    fn set_note(&mut self, key: String, value: String);
    fn get_note(&self, key: &str) -> Option<String>;

    fn set_tag(&mut self, key: &str, value: String);
    fn get_tag(&self, key: &str) -> Option<String>;

    fn set_do_not_spend(&mut self, key: &str, value: bool);
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
    fn set_note(&mut self, key: String, value: String) {
        self.notes_store.insert(key.to_string(), value);
    }
    fn get_note(&self, key: &str) -> Option<String> {
        self.notes_store.get(key).cloned()
    }
    fn set_tag(&mut self, key: &str, value: String) {
        self.tag_store.insert(key.to_string(), value);
    }
    fn get_tag(&self, key: &str) -> Option<String> {
        self.tag_store.get(key).cloned()
    }
    fn set_do_not_spend(&mut self, key: &str, value: bool) {
        self.do_not_spend_store.insert(key.to_string(), value);
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
