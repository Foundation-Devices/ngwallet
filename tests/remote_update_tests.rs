/// RemoteUpdate  tests
/// All validation logic fires before any wallet data is touched, so these
/// tests use empty `wallet_update` payloads

#[cfg(test)]
#[cfg(feature = "envoy")]
mod tests {
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::rusqlite::Connection;
    use ngwallet::account::{Descriptor, NgAccount, RemoteUpdate};
    use ngwallet::config::{AddressType, NgAccountBuilder};
    use std::sync::{Arc, Mutex};

    const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";

    fn make_account() -> NgAccount<Connection> {
        let descriptors = vec![Descriptor {
            internal: INTERNAL_DESCRIPTOR.to_string(),
            external: None,
            bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
        }];
        NgAccountBuilder::default()
            .name("Test".to_string())
            .color("blue".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2wpkh)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .account_path(None)
            .network(Network::Signet)
            .id("test-account-id".to_string())
            .build_in_memory()
            .unwrap()
    }

    /// Build a valid payload with the given sequence and no wallet data.
    fn make_payload(account: &NgAccount<Connection>, sequence: u64) -> Vec<u8> {
        let cfg = account.config.read().unwrap();
        RemoteUpdate::new(
            cfg.id.clone(),
            cfg.network,
            cfg.descriptor_hash(),
            sequence,
            None,
            vec![],
        )
        .serialize()
    }

    /// Applying the same payload a second time must be rejected.
    ///
    /// Before the fix `update()` had no sequence counter so the same payload
    /// could be applied more than once.
    #[test]
    fn same_remote_update_applied_twice_is_rejected() {
        let account = make_account();

        // Both payloads are stamped with sequence=1 before either is applied.
        let payload1 = make_payload(&account, 1);
        let payload2 = make_payload(&account, 1);

        account.update(payload1).unwrap();
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 1);

        let err = account.update(payload2).unwrap_err();
        assert!(
            err.to_string().contains("not newer"),
            "replay should be rejected, got: {err}"
        );
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 1);
    }

    #[test]
    fn update_from_wrong_account_is_rejected() {
        let account = make_account();
        let cfg = account.config.read().unwrap();
        let payload = RemoteUpdate::new(
            "wrong-account-id".to_string(),
            cfg.network,
            cfg.descriptor_hash(),
            cfg.last_remote_sequence + 1,
            None,
            vec![],
        )
        .serialize();
        drop(cfg);

        let err = account.update(payload).unwrap_err();
        assert!(
            err.to_string().contains("account_id mismatch"),
            "wrong account_id should be rejected, got: {err}"
        );
    }

    #[test]
    fn update_with_wrong_network_is_rejected() {
        let account = make_account();
        let cfg = account.config.read().unwrap();
        let payload = RemoteUpdate::new(
            cfg.id.clone(),
            Network::Bitcoin,
            cfg.descriptor_hash(),
            cfg.last_remote_sequence + 1,
            None,
            vec![],
        )
        .serialize();
        drop(cfg);

        let err = account.update(payload).unwrap_err();
        assert!(
            err.to_string().contains("network mismatch"),
            "wrong network should be rejected, got: {err}"
        );
    }

    #[test]
    fn update_with_wrong_descriptor_hash_is_rejected() {
        let account = make_account();
        let cfg = account.config.read().unwrap();
        let payload = RemoteUpdate::new(
            cfg.id.clone(),
            cfg.network,
            [0xdeu8; 32],
            cfg.last_remote_sequence + 1,
            None,
            vec![],
        )
        .serialize();
        drop(cfg);

        let err = account.update(payload).unwrap_err();
        assert!(
            err.to_string().contains("descriptor hash mismatch"),
            "wrong descriptor hash should be rejected, got: {err}"
        );
    }

    /// Metadata carrying a different `preferred_address_type` must be rejected.
    #[test]
    fn metadata_changing_preferred_address_type_is_rejected() {
        let account = make_account();
        let cfg = account.config.read().unwrap();
        let mut modified = cfg.clone();
        modified.preferred_address_type = AddressType::P2tr;
        let payload = RemoteUpdate::new(
            cfg.id.clone(),
            cfg.network,
            cfg.descriptor_hash(),
            cfg.last_remote_sequence + 1,
            Some(modified),
            vec![],
        )
        .serialize();
        drop(cfg);

        let err = account.update(payload).unwrap_err();
        assert!(
            err.to_string().contains("preferred_address_type"),
            "preferred_address_type change should be rejected, got: {err}"
        );
        assert_eq!(
            account.config.read().unwrap().preferred_address_type,
            AddressType::P2wpkh,
        );
    }

    #[test]
    fn stale_sequence_is_rejected() {
        let account = make_account();

        account.update(make_payload(&account, 3)).unwrap();
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 3);

        let cfg = account.config.read().unwrap();
        let stale = RemoteUpdate::new(
            cfg.id.clone(),
            cfg.network,
            cfg.descriptor_hash(),
            2,
            None,
            vec![],
        )
        .serialize();
        drop(cfg);

        let err = account.update(stale).unwrap_err();
        assert!(
            err.to_string().contains("not newer"),
            "stale sequence should be rejected, got: {err}"
        );
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 3);
    }
}
