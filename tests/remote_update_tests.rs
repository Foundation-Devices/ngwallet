//! RemoteUpdate tests
//! All validation logic fires before any wallet data is touched
//! tests use empty `wallet_update` payloads

#[cfg(test)]
#[cfg(feature = "envoy")]
mod tests {
    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bdk_wallet::bitcoin::{Network, PrivateKey};
    use bdk_wallet::miniscript::Descriptor as MiniscriptDescriptor;
    use bdk_wallet::miniscript::descriptor::{DescriptorPublicKey, checksum::desc_checksum};
    use bdk_wallet::rusqlite::Connection;
    use ngwallet::account::{Descriptor as AccountDescriptor, NgAccount, RemoteUpdate};
    use ngwallet::config::{AddressType, NgAccountBuilder, NgAccountConfig, NgDescriptor};
    use std::sync::{Arc, Mutex};

    const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";

    fn make_account() -> NgAccount<Connection> {
        let descriptors = vec![AccountDescriptor {
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

    fn base_config() -> NgAccountConfig {
        make_account().config.read().unwrap().clone()
    }

    fn ng_descriptor(internal: String, external: Option<String>) -> NgDescriptor {
        NgDescriptor {
            internal,
            external,
            address_type: AddressType::P2tr,
            export_addr_hint: Some(AddressType::P2ShWpkh),
        }
    }

    fn config_with_descriptor(internal: String, external: Option<String>) -> NgAccountConfig {
        let mut config = base_config();
        config.descriptors = vec![ng_descriptor(internal, external)];
        config
    }

    fn current_payload(config: NgAccountConfig) -> Vec<u8> {
        RemoteUpdate::new(
            config.id.clone(),
            config.network,
            config.descriptor_hash(),
            0,
            Some(config),
            vec![],
        )
        .serialize()
    }

    fn master_xprv(network: Network) -> Xpriv {
        Xpriv::new_master(network, &[0x2a; 32]).unwrap()
    }

    fn descriptor_with_key(key: impl std::fmt::Display) -> String {
        public_descriptor(&format!("wpkh({key}/0/*)"))
    }

    fn public_descriptor(descriptor: &str) -> String {
        let secp = Secp256k1::new();
        MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, descriptor)
            .unwrap()
            .0
            .to_string()
    }

    fn checksummed(descriptor: &str) -> String {
        format!("{descriptor}#{}", desc_checksum(descriptor).unwrap())
    }

    fn private_key(byte: u8, network: Network) -> PrivateKey {
        PrivateKey::new(SecretKey::from_slice(&[byte; 32]).unwrap(), network)
    }

    fn wif(byte: u8) -> PrivateKey {
        private_key(byte, Network::Signet)
    }

    fn slip132_private_key(version: [u8; 4], network: Network) -> String {
        let canonical = master_xprv(network).to_string();
        let mut payload = bdk_wallet::bitcoin::base58::decode_check(&canonical).unwrap();
        payload[..4].copy_from_slice(&version);
        bdk_wallet::bitcoin::base58::encode_check(&payload)
    }

    fn unsafe_descriptors() -> Vec<(&'static str, String)> {
        // All private SLIP-132 versions from SLIP-0132: yprv, zprv, Yprv,
        // Zprv and their testnet equivalents uprv, vprv, Uprv, Vprv.
        let slip132_versions = [
            ("yprv", [0x04, 0x9d, 0x78, 0x78], Network::Bitcoin),
            ("zprv", [0x04, 0xb2, 0x43, 0x0c], Network::Bitcoin),
            ("Yprv", [0x02, 0x95, 0xb0, 0x05], Network::Bitcoin),
            ("Zprv", [0x02, 0xaa, 0x7a, 0x99], Network::Bitcoin),
            ("uprv", [0x04, 0x4a, 0x4e, 0x28], Network::Signet),
            ("vprv", [0x04, 0x5f, 0x18, 0xbc], Network::Signet),
            ("Uprv", [0x02, 0x42, 0x85, 0xb5], Network::Signet),
            ("Vprv", [0x02, 0x57, 0x50, 0x48], Network::Signet),
        ];

        let mut cases: Vec<_> = slip132_versions
            .into_iter()
            .map(|(name, version, network)| {
                (
                    name,
                    format!("wpkh({}/0/*)", slip132_private_key(version, network)),
                )
            })
            .collect();

        let xprv = master_xprv(Network::Bitcoin);
        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv);
        let valid_public = descriptor_with_key(xpub);
        let descriptor_body = valid_public.split('#').next().unwrap();
        let unknown_version = slip132_private_key([0x01, 0x02, 0x03, 0x04], Network::Bitcoin);
        let origin_wif = wif(3).to_wif();
        let public_key = wif(4).public_key(&secp);
        let uncompressed_public_key =
            PrivateKey::new_uncompressed(SecretKey::from_slice(&[5; 32]).unwrap(), Network::Signet)
                .public_key(&secp);
        cases.extend([
            ("malformed checksum", format!("{descriptor_body}#00000000")),
            ("malformed syntax", "wpkh(not-a-key".to_string()),
            (
                "malformed hash literal",
                format!("wsh(and_v(v:pk({public_key}),sha256(not-a-hash)))"),
            ),
            (
                "unknown extended-key version",
                format!("wpkh({unknown_version}/0/*)"),
            ),
            ("multipath xprv", format!("wpkh({xprv}/<0;1>/*)")),
            ("hardened wildcard xprv", format!("wpkh({xprv}/*h)")),
            ("hardened wildcard xpub", format!("wpkh({xpub}/*h)")),
            ("hardened path xpub", format!("wpkh({xpub}/0'/*)")),
            (
                "uncompressed public key in wpkh",
                format!("wpkh({uncompressed_public_key})"),
            ),
            (
                "origin-annotated WIF",
                format!("wpkh([deadbeef/84h]{origin_wif})"),
            ),
        ]);
        cases
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

    #[test]
    fn descriptor_hash_retains_released_raw_byte_semantics() {
        const LEGACY_PRIVATE_HASH: [u8; 32] = [
            0x03, 0xff, 0xd9, 0x84, 0xd5, 0xd9, 0xbb, 0xf4, 0x59, 0xc6, 0x4c, 0x4e, 0x2c, 0x6a,
            0xa2, 0xa1, 0x82, 0x21, 0x4e, 0x8d, 0x3d, 0x91, 0x79, 0x1f, 0xb5, 0xbf, 0x07, 0x28,
            0x30, 0x83, 0xc7, 0x7f,
        ];
        const LEGACY_CHECKSUMLESS_PUBLIC_HASH: [u8; 32] = [
            0x45, 0x01, 0xc1, 0x91, 0x58, 0xe1, 0x24, 0x24, 0x56, 0x1a, 0x0e, 0x9f, 0x19, 0x8f,
            0xf4, 0xb4, 0x67, 0x33, 0x87, 0x9c, 0x3b, 0x72, 0x52, 0xca, 0x2a, 0x52, 0x7c, 0x44,
            0x06, 0xda, 0xa1, 0xb5,
        ];
        const CHECKSUMLESS_PUBLIC: &str =
            "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

        let private_config = config_with_descriptor(INTERNAL_DESCRIPTOR.to_string(), None);
        assert!(private_config.multisig.is_none());
        assert_eq!(private_config.descriptor_hash(), LEGACY_PRIVATE_HASH);

        let watch_only = config_with_descriptor(CHECKSUMLESS_PUBLIC.to_string(), None);
        assert!(watch_only.multisig.is_none());
        assert_eq!(
            watch_only.descriptor_hash(),
            LEGACY_CHECKSUMLESS_PUBLIC_HASH
        );
        let canonical = config_with_descriptor(public_descriptor(CHECKSUMLESS_PUBLIC), None);
        assert_ne!(watch_only.descriptor_hash(), canonical.descriptor_hash());

        // A queued update produced by the released raw-byte algorithm remains
        // valid after upgrading this consumer.
        let account = make_account();
        let config = account.config.read().unwrap();
        let queued = RemoteUpdate::new(
            config.id.clone(),
            config.network,
            LEGACY_PRIVATE_HASH,
            1,
            None,
            vec![],
        )
        .serialize();
        drop(config);
        account.update(queued).unwrap();
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 1);
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

    #[test]
    fn outbound_publicizes_signet_wif_in_both_descriptor_fields() {
        let secp = Secp256k1::new();
        let internal_wif = wif(1);
        let external_wif = wif(2);
        let internal = format!("wpkh({})", internal_wif.to_wif());
        let external = format!("wpkh({})", external_wif.to_wif());
        let expected_internal =
            public_descriptor(&format!("wpkh({})", internal_wif.public_key(&secp)));
        let expected_external =
            public_descriptor(&format!("wpkh({})", external_wif.public_key(&secp)));
        let config = config_with_descriptor(internal, Some(external));
        let original_hash = config.descriptor_hash();

        let remote = RemoteUpdate::deserialize(&config.to_remote_update()).unwrap();
        let metadata = remote.metadata.unwrap();
        assert_eq!(remote.descriptor_hash, original_hash);
        assert_ne!(metadata.descriptor_hash(), original_hash);
        assert!(!metadata.has_private_descriptors());
        assert_eq!(metadata.descriptors.len(), 1);
        assert_eq!(metadata.descriptors[0].internal, expected_internal);
        assert_eq!(
            metadata.descriptors[0].external.as_deref(),
            Some(expected_external.as_str())
        );
        assert_eq!(metadata.descriptors[0].address_type, AddressType::P2tr);
        assert_eq!(
            metadata.descriptors[0].export_addr_hint,
            Some(AddressType::P2ShWpkh)
        );
    }

    #[test]
    fn outbound_publicizes_mainnet_xprv_and_testnet_tprv() {
        for network in [Network::Bitcoin, Network::Signet] {
            let secp = Secp256k1::new();
            let xprv = master_xprv(network);
            let source = format!("wpkh({xprv}/0/*)");
            let expected = descriptor_with_key(Xpub::from_priv(&secp, &xprv));
            let mut config = config_with_descriptor(source, None);
            config.network = network;
            let original_hash = config.descriptor_hash();

            let remote = RemoteUpdate::deserialize(&config.to_remote_update()).unwrap();
            let metadata = remote.metadata.unwrap();
            assert_eq!(remote.descriptor_hash, original_hash, "{network}");
            assert_ne!(metadata.descriptor_hash(), original_hash, "{network}");
            assert!(!metadata.has_private_descriptors(), "{network}");
            assert_eq!(metadata.descriptors[0].internal, expected, "{network}");
            assert_eq!(metadata.descriptors[0].address_type, AddressType::P2tr);
            assert_eq!(
                metadata.descriptors[0].export_addr_hint,
                Some(AddressType::P2ShWpkh)
            );
        }
    }

    #[test]
    fn unsafe_outbound_descriptor_clears_the_entire_vector() {
        let public = descriptor_with_key(Xpub::from_priv(
            &Secp256k1::new(),
            &master_xprv(Network::Bitcoin),
        ));

        for (case, unsafe_descriptor) in unsafe_descriptors() {
            let mut config = base_config();
            config.descriptors = vec![
                ng_descriptor(public.clone(), None),
                ng_descriptor(unsafe_descriptor, None),
            ];
            let original_hash = config.descriptor_hash();

            let remote = RemoteUpdate::deserialize(&config.to_remote_update()).unwrap();
            assert_eq!(remote.descriptor_hash, original_hash, "{case}");
            assert!(
                remote.metadata.unwrap().descriptors.is_empty(),
                "unsafe case {case} must clear all outbound descriptors"
            );
        }

        let (_, unsafe_external) = unsafe_descriptors()
            .into_iter()
            .find(|(case, _)| *case == "malformed syntax")
            .unwrap();
        let mut config = base_config();
        config.descriptors = vec![ng_descriptor(public.clone(), Some(unsafe_external))];
        let remote = RemoteUpdate::deserialize(&config.to_remote_update()).unwrap();
        assert!(remote.metadata.unwrap().descriptors.is_empty());
    }

    #[test]
    fn recognized_secrets_are_sanitized_after_current_and_legacy_decoding() {
        let secp = Secp256k1::new();
        let xprv = master_xprv(Network::Bitcoin);
        let tprv = master_xprv(Network::Signet);
        let wif_key = wif(7);
        let secret_cases = [
            (
                Network::Signet,
                format!("wpkh({})", wif_key.to_wif()),
                public_descriptor(&format!("wpkh({})", wif_key.public_key(&secp))),
            ),
            (
                Network::Bitcoin,
                format!("wpkh({xprv}/0/*)"),
                descriptor_with_key(Xpub::from_priv(&secp, &xprv)),
            ),
            (
                Network::Signet,
                format!("wpkh({tprv}/0/*)"),
                descriptor_with_key(Xpub::from_priv(&secp, &tprv)),
            ),
        ];

        for (network, secret, expected) in secret_cases {
            let external_key = private_key(8, network);
            let external_secret = format!("wpkh({})", external_key.to_wif());
            let expected_external =
                public_descriptor(&format!("wpkh({})", external_key.public_key(&secp)));
            let mut config = config_with_descriptor(secret, Some(external_secret));
            config.network = network;

            let current = NgAccountConfig::from_remote(current_payload(config.clone())).unwrap();
            assert!(!current.has_private_descriptors());
            assert_eq!(current.descriptors[0].internal, expected);
            assert_eq!(
                current.descriptors[0].external.as_deref(),
                Some(expected_external.as_str())
            );

            let legacy = NgAccountConfig::from_remote(make_legacy_payload(Some(config))).unwrap();
            assert!(!legacy.has_private_descriptors());
            assert_eq!(legacy.descriptors[0].internal, expected);
            assert_eq!(
                legacy.descriptors[0].external.as_deref(),
                Some(expected_external.as_str())
            );
        }
    }

    #[test]
    fn unsafe_current_and_legacy_inbound_metadata_is_rejected() {
        for (case, unsafe_descriptor) in unsafe_descriptors() {
            let config = config_with_descriptor(unsafe_descriptor.clone(), None);

            let current_err =
                NgAccountConfig::from_remote(current_payload(config.clone())).unwrap_err();
            assert_eq!(
                current_err.to_string(),
                "remote metadata contains an unsafe descriptor",
                "unexpected current error for {case}"
            );

            let legacy_err =
                NgAccountConfig::from_remote(make_legacy_payload(Some(config))).unwrap_err();
            assert_eq!(
                legacy_err.to_string(),
                "remote metadata contains an unsafe descriptor",
                "unexpected legacy error for {case}"
            );
        }
    }

    #[test]
    fn watch_only_descriptors_round_trip_exactly_in_current_and_legacy_payloads() {
        let secp = Secp256k1::new();
        let main_xpub = Xpub::from_priv(&secp, &master_xprv(Network::Bitcoin));
        let test_xpub = Xpub::from_priv(&secp, &master_xprv(Network::Signet));
        let raw_key_one = wif(11).public_key(&secp);
        let raw_key_two = wif(12).public_key(&secp);
        // The `h` notation is valid but serializes canonically as `'`. Keeping
        // it here catches accidental normalization of watch-only metadata.
        let noncanonical_xpub = checksummed(&format!("wpkh([deadbeef/84h]{main_xpub}/0/*)"));
        let checksummed_tpub = descriptor_with_key(test_xpub);
        let tpub_without_checksum = checksummed_tpub.split('#').next().unwrap().to_string();
        let cases = [
            ("xpub", noncanonical_xpub),
            ("tpub", checksummed_tpub),
            ("tpub without checksum", tpub_without_checksum),
            (
                "raw public key",
                public_descriptor(&format!("wpkh({raw_key_one})")),
            ),
            (
                "nested watch-only",
                public_descriptor(&format!(
                    "sh(wsh(sortedmulti(2,{raw_key_one},{raw_key_two})))"
                )),
            ),
        ];

        for (case, watch_only) in cases {
            let config = config_with_descriptor(watch_only.clone(), Some(watch_only.clone()));
            let expected_descriptors = config.descriptors.clone();
            let current_payload = config.clone().to_remote_update();
            let current_wire = RemoteUpdate::deserialize(&current_payload).unwrap();
            let current_wire_metadata = current_wire.metadata.unwrap();
            assert_eq!(
                current_wire_metadata.descriptors, expected_descriptors,
                "{case}"
            );
            assert_eq!(current_wire_metadata.descriptors[0].internal, watch_only);
            assert_eq!(
                current_wire_metadata.descriptors[0].external.as_deref(),
                Some(watch_only.as_str()),
                "{case}"
            );
            let current = NgAccountConfig::from_remote(current_payload).unwrap();
            assert_eq!(current.descriptors, expected_descriptors, "{case}");
            assert_eq!(current.descriptors[0].internal, watch_only, "{case}");

            let legacy = NgAccountConfig::from_remote(make_legacy_payload(Some(config))).unwrap();
            assert_eq!(legacy.descriptors, expected_descriptors, "{case}");
            assert_eq!(legacy.descriptors[0].internal, watch_only, "{case}");
            assert_eq!(
                legacy.descriptors[0].external.as_deref(),
                Some(watch_only.as_str()),
                "{case}"
            );
        }
    }

    #[test]
    fn has_private_descriptors_is_fail_closed() {
        let watch_only = descriptor_with_key(Xpub::from_priv(
            &Secp256k1::new(),
            &master_xprv(Network::Bitcoin),
        ));
        assert!(!config_with_descriptor(watch_only, None).has_private_descriptors());

        let wif_descriptor = format!("wpkh({})", wif(21).to_wif());
        assert!(config_with_descriptor(wif_descriptor, None).has_private_descriptors());

        for network in [Network::Bitcoin, Network::Signet] {
            let xprv_descriptor = format!("wpkh({}/0/*)", master_xprv(network));
            assert!(config_with_descriptor(xprv_descriptor, None).has_private_descriptors());
        }

        for (case, unsafe_descriptor) in unsafe_descriptors() {
            assert!(
                config_with_descriptor(unsafe_descriptor, None).has_private_descriptors(),
                "unsafe case {case} must be treated as private"
            );
        }
    }

    /// Pre-3.5 wire shape: no binding fields. Element type of the empty
    /// `wallet_update` is irrelevant to the encoding.
    fn make_legacy_payload(metadata: Option<ngwallet::config::NgAccountConfig>) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct LegacyRemoteUpdate {
            metadata: Option<ngwallet::config::NgAccountConfig>,
            wallet_update: Vec<()>,
        }

        minicbor_serde::to_vec(&LegacyRemoteUpdate {
            metadata,
            wallet_update: vec![],
        })
        .unwrap()
    }

    /// Config-exchange payloads from pre-3.5 peers (older Prime firmware)
    /// lack the binding fields; `from_remote` must still accept them.
    #[test]
    fn legacy_config_payload_is_accepted_by_from_remote() {
        let account = make_account();
        let cfg = account.config.read().unwrap().clone();
        let payload = make_legacy_payload(Some(cfg.clone()));

        let decoded = ngwallet::config::NgAccountConfig::from_remote(payload).unwrap();
        assert_eq!(decoded.id, cfg.id);
        assert_eq!(decoded.name, cfg.name);
        assert_eq!(decoded.network, cfg.network);
    }

    /// The current 6-field shape must keep decoding through `from_remote`.
    #[test]
    fn current_config_payload_is_accepted_by_from_remote() {
        let account = make_account();
        let cfg = account.config.read().unwrap().clone();
        let payload = cfg.clone().to_remote_update();

        let decoded = ngwallet::config::NgAccountConfig::from_remote(payload).unwrap();
        assert_eq!(decoded.id, cfg.id);
    }

    /// The wallet-update path must stay strict: legacy payloads carry none of
    /// the binding fields, so `update()` rejects them outright.
    #[test]
    fn legacy_payload_is_rejected_by_update() {
        let account = make_account();
        let payload = make_legacy_payload(None);

        account.update(payload).unwrap_err();
        assert_eq!(account.config.read().unwrap().last_remote_sequence, 0);
    }
}
