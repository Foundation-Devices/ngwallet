// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Versioned Foundation/Liana wallet-policy envelope.
//!
//! The envelope is a transport adapter. [`super::WalletPolicy`] remains the
//! canonical persisted representation so additional coordinators can be added
//! without changing the signing trust boundary.

use {
    super::{Error, MAX_DESCRIPTOR_BYTES, MAX_KEYS, Result},
    bdk_wallet::{
        bitcoin::{
            Network, NetworkKind,
            hashes::{Hash, sha256},
        },
        miniscript::{Descriptor, DescriptorPublicKey},
    },
    serde::{Deserialize, Serialize},
    std::{collections::HashSet, str::FromStr},
};

pub const POLICY_FORMAT: &str = "passport-wallet-policy";
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_JSON_BYTES: usize = 4_096;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_TEMPLATE_BYTES: usize = 2_048;
pub const MAX_NAME_BYTES: usize = 20;

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyNetwork {
    Btc,
    Tbtc,
}

impl PolicyNetwork {
    pub fn from_network(network: Network) -> Result<Self> {
        match network {
            Network::Bitcoin => Ok(Self::Btc),
            Network::Signet | Network::Testnet | Network::Testnet4 | Network::Regtest => {
                Ok(Self::Tbtc)
            }
        }
    }

    pub fn network_kind(self) -> NetworkKind {
        match self {
            Self::Btc => NetworkKind::Main,
            Self::Tbtc => NetworkKind::Test,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::Btc => "BTC",
            Self::Tbtc => "TBTC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRegistration {
    pub format: String,
    pub version: u8,
    pub name: String,
    pub network: PolicyNetwork,
    pub template: String,
    pub keys: Vec<String>,
    pub policy_id: String,
}

impl PolicyRegistration {
    pub fn from_json(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data.len() > MAX_JSON_BYTES {
            return Err(Error::Parse(
                "wallet-policy JSON is empty or too large".into(),
            ));
        }
        validate_json_depth(data)?;
        let registration = serde_json::from_slice::<Self>(data)
            .map_err(|error| Error::Parse(format!("invalid wallet-policy JSON: {error}")))?;
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != POLICY_FORMAT || self.version != PROTOCOL_VERSION {
            return Err(Error::Parse("unsupported wallet-policy envelope".into()));
        }
        validate_printable(&self.name, 1, MAX_NAME_BYTES, "wallet name")?;
        validate_printable(&self.template, 1, MAX_TEMPLATE_BYTES, "descriptor template")?;
        if !self.template.starts_with("wsh(") || !self.template.ends_with(')') {
            return Err(Error::Unsupported(
                "initial wallet-policy support is limited to top-level wsh()".into(),
            ));
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(Error::Parse(format!(
                "wallet policy must contain 1 to {MAX_KEYS} keys"
            )));
        }
        if placeholder_order(&self.template)? != (0..self.keys.len()).collect::<Vec<_>>() {
            return Err(Error::Parse(
                "wallet-policy keys must appear in canonical first-use order".into(),
            ));
        }
        let mut unique = HashSet::new();
        for key in &self.keys {
            let parsed = DescriptorPublicKey::from_str(key)
                .map_err(|error| Error::Parse(format!("invalid wallet-policy key: {error}")))?;
            if parsed.to_string() != *key || !unique.insert(key) {
                return Err(Error::Parse(
                    "wallet-policy keys must be canonical and unique".into(),
                ));
            }
        }
        if self.full_descriptor().len() > MAX_DESCRIPTOR_BYTES {
            return Err(Error::Parse("wallet-policy descriptor is too large".into()));
        }
        let canonical = self.canonical_descriptor()?;
        if canonical.rsplit_once('#').map(|(body, _)| body) != Some(self.full_descriptor().as_str())
        {
            return Err(Error::Parse(
                "wallet-policy descriptor is not canonical".into(),
            ));
        }
        if self.policy_id.len() != 64
            || !self.policy_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.policy_id != self.calculate_policy_id()
        {
            return Err(Error::Parse("wallet-policy identity mismatch".into()));
        }
        Ok(())
    }

    pub fn full_descriptor(&self) -> String {
        let mut descriptor = self.template.clone();
        for index in (0..self.keys.len()).rev() {
            descriptor = descriptor.replace(&format!("@{index}"), &self.keys[index]);
        }
        descriptor
    }

    pub fn canonical_descriptor(&self) -> Result<String> {
        Descriptor::<DescriptorPublicKey>::from_str(&self.full_descriptor())
            .map(|descriptor| descriptor.to_string())
            .map_err(|error| Error::Parse(format!("invalid reconstructed descriptor: {error}")))
    }

    pub fn calculate_policy_id(&self) -> String {
        let mut payload = b"Passport Wallet Policy\0".to_vec();
        payload.push(PROTOCOL_VERSION);
        encode_field(&mut payload, self.network.text());
        encode_field(&mut payload, &self.template);
        compact_size(&mut payload, self.keys.len());
        for key in &self.keys {
            encode_field(&mut payload, key);
        }
        sha256::Hash::hash(&payload).to_string()
    }
}

pub(crate) fn descriptor_to_template(body: &str) -> Result<(String, Vec<String>)> {
    if body.len() > MAX_DESCRIPTOR_BYTES || !body.is_ascii() {
        return Err(Error::Parse("descriptor is non-ASCII or too large".into()));
    }
    let bytes = body.as_bytes();
    let mut output = String::with_capacity(body.len());
    let mut keys = Vec::<String>::new();
    let mut position = 0usize;
    while position < bytes.len() {
        if bytes[position] != b'[' {
            output.push(char::from(bytes[position]));
            position += 1;
            continue;
        }
        let close = body[position + 1..]
            .find(']')
            .map(|offset| position + 1 + offset)
            .ok_or_else(|| Error::Parse("key origin is incomplete".into()))?;
        let mut xpub_end = close + 1;
        while xpub_end < bytes.len() && BASE58.contains(&bytes[xpub_end]) {
            xpub_end += 1;
        }
        if xpub_end == close + 1 {
            return Err(Error::Parse(
                "key origin is not followed by an extended public key".into(),
            ));
        }
        let raw_key = &body[position..xpub_end];
        let key = DescriptorPublicKey::from_str(raw_key)
            .map_err(|error| Error::Parse(format!("invalid descriptor key: {error}")))?
            .to_string();
        let (suffix, next) = if body[xpub_end..].starts_with("/**") {
            ("/**".to_owned(), xpub_end + 3)
        } else if body[xpub_end..].starts_with("/<") {
            let relative_end = body[xpub_end + 2..]
                .find(">/*")
                .ok_or_else(|| Error::Parse("multipath suffix is incomplete".into()))?;
            let suffix_end = xpub_end + 2 + relative_end;
            let branches = &body[xpub_end + 2..suffix_end];
            let mut parts = branches.split(';');
            let first = canonical_number(parts.next())?;
            let second = canonical_number(parts.next())?;
            if parts.next().is_some() || first == second {
                return Err(Error::Parse(
                    "exactly two distinct multipath branches are required".into(),
                ));
            }
            (format!("/<{first};{second}>/*"), suffix_end + 3)
        } else {
            return Err(Error::Parse(
                "extended keys must end in /** or /<M;N>/*".into(),
            ));
        };
        let key_index = match keys.iter().position(|existing| existing == &key) {
            Some(index) => index,
            None => {
                if keys.len() == MAX_KEYS {
                    return Err(Error::Parse("too many wallet-policy keys".into()));
                }
                keys.push(key);
                keys.len() - 1
            }
        };
        output.push_str(&format!("@{key_index}{suffix}"));
        position = next;
    }
    Ok((output, keys))
}

fn placeholder_order(template: &str) -> Result<Vec<usize>> {
    let bytes = template.as_bytes();
    let mut cursor = 0usize;
    let mut order = Vec::new();
    while cursor < bytes.len() {
        if bytes[cursor] != b'@' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if start == cursor {
            return Err(Error::Parse("invalid wallet-policy key placeholder".into()));
        }
        let index = template[start..cursor]
            .parse::<usize>()
            .map_err(|_| Error::Parse("invalid wallet-policy key placeholder".into()))?;
        if !order.contains(&index) {
            order.push(index);
        }
    }
    Ok(order)
}

fn canonical_number(number: Option<&str>) -> Result<u32> {
    let number = number.ok_or_else(|| Error::Parse("missing branch number".into()))?;
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
    {
        return Err(Error::Parse("branch number is not canonical".into()));
    }
    let value = number
        .parse::<u32>()
        .map_err(|_| Error::Parse("branch number is too large".into()))?;
    if value >= (1 << 31) {
        return Err(Error::Parse("branch number is too large".into()));
    }
    Ok(value)
}

fn validate_printable(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    if !(min..=max).contains(&value.len())
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| !(32..=126).contains(&byte))
    {
        return Err(Error::Parse(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_json_depth(data: &[u8]) -> Result<()> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in data {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(Error::Parse(
                        "wallet-policy JSON nesting exceeds limit".into(),
                    ));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn compact_size(output: &mut Vec<u8>, value: usize) {
    if value < 253 {
        output.push(value as u8);
    } else if value <= u16::MAX as usize {
        output.push(253);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        output.push(254);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

fn encode_field(output: &mut Vec<u8>, value: &str) {
    compact_size(output, value.len());
    output.extend_from_slice(value.as_bytes());
}
