//! The network config: the liteservers a client can reach.

use serde::Deserialize;

use crate::codec::base64_decode;
use crate::{BlockIdExt, Error};

/// How far behind the local clock a proven head may be, by default.
///
/// Ten minutes. The bound has to cover two things at once: a server serving a block it
/// has been sitting on, and the walk's own duration, since a cold sync targets a head it
/// read at the start and takes a couple of minutes to reach it. A tighter bound would
/// refuse an honest cold sync on a slow link, which is why this is generous and
/// [`Config::with_max_head_age`] exists for a caller who knows better.
const DEFAULT_MAX_HEAD_AGE: u32 = 600;

/// The public network parameters a client needs to reach TON.
///
/// A config lists the liteservers to connect to and names the block a client anchors its
/// trust at. It holds only public data and never a secret. The DHT section a config also
/// carries is not read.
#[derive(Debug, Clone)]
pub struct Config {
    liteservers: Vec<LiteServer>,
    init_block: Option<BlockIdExt>,
    max_head_age: u32,
}

/// One liteserver: an address ready to dial and its public key.
#[derive(Debug, Clone)]
pub(crate) struct LiteServer {
    pub(crate) addr: String,
    pub(crate) key: [u8; 32],
}

impl Config {
    /// Returns a config for TON mainnet from a bundled snapshot, taken 2026-07-21.
    ///
    /// The snapshot is a point-in-time copy of the public mainnet config and can go stale
    /// as liteservers rotate. To use a current config, fetch `global.config.json` and pass
    /// it to [`Config::from_json`].
    ///
    /// Its [`init_block`](Self::init_block) is at masterchain sequence number 46894135,
    /// which is where a first sync starts walking. That block is what the network
    /// publishes rather than one this library chose, and the further it recedes the
    /// longer a first sync takes, so refreshing this snapshot belongs to cutting a
    /// release rather than to housekeeping.
    #[must_use]
    pub fn mainnet() -> Config {
        // The bundled snapshot is checked in and parsed at build of the caller; it is
        // valid by construction and covered by a test.
        Config::from_json(include_str!("mainnet.config.json"))
            .expect("the bundled mainnet config parses")
    }

    /// Parses a config from the TON `global.config.json` format.
    ///
    /// Reads the liteserver list and the validator section's init block; the rest is
    /// ignored. Each liteserver's `ip` is a signed 32-bit integer in that format, decoded
    /// here to dotted-quad form, and a block's shard is a signed 64-bit integer decoded
    /// to the prefix mask a block identity uses.
    ///
    /// A config with no init block parses. It leaves a client without a starting point
    /// for a cold sync, which is a failure at [`crate::Client::sync`] rather than here,
    /// because a caller supplying their own anchor never needs one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the JSON is malformed, has no liteserver list, a
    /// liteserver has an unsupported key type or a key that is not 32 bytes, or the init
    /// block's hashes are not 32 base64 bytes.
    pub fn from_json(json: &str) -> Result<Config, Error> {
        let raw: RawConfig =
            serde_json::from_str(json).map_err(|e| Error::Config(e.to_string()))?;
        if raw.liteservers.is_empty() {
            return Err(Error::Config("config has no liteservers".to_string()));
        }

        let mut liteservers = Vec::with_capacity(raw.liteservers.len());
        for server in raw.liteservers {
            if server.id.key_type != "pub.ed25519" {
                return Err(Error::Config(format!(
                    "unsupported liteserver key type `{}`",
                    server.id.key_type
                )));
            }
            let key: [u8; 32] = base64_decode(&server.id.key)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    Error::Config("liteserver key is not 32 base64 bytes".to_string())
                })?;

            let octets = (server.ip as u32).to_be_bytes();
            let addr = format!(
                "{}.{}.{}.{}:{}",
                octets[0], octets[1], octets[2], octets[3], server.port
            );
            liteservers.push(LiteServer { addr, key });
        }

        let init_block = match raw.validator.and_then(|validator| validator.init_block) {
            Some(block) => Some(BlockIdExt::new(
                block.workchain,
                block.shard as u64,
                block.seqno,
                hash(&block.root_hash, "init block root hash")?,
                hash(&block.file_hash, "init block file hash")?,
            )),
            None => None,
        };

        Ok(Config {
            liteservers,
            init_block,
            max_head_age: DEFAULT_MAX_HEAD_AGE,
        })
    }

    /// The block a client anchors its trust at before it has proved anything.
    ///
    /// This is the `validator.init_block` field of the TON config format, and it is the
    /// only thing a verified read takes on trust from the chain's side of the world. A
    /// caller who wants a different root of trust changes it here or hands their own
    /// block to [`Client::connect_from`](crate::Client::connect_from).
    ///
    /// It is not the only trusted input. The other is the local clock, which is the one
    /// thing separating a current block from a genuine old one replayed: see
    /// [`max_head_age`](Self::max_head_age).
    #[must_use]
    pub fn init_block(&self) -> Option<&BlockIdExt> {
        self.init_block.as_ref()
    }

    /// Sets how far behind the local clock a proven head may be, in seconds.
    ///
    /// A liteserver can serve a real block that is old, and nothing in a proof says when
    /// it was served, so a block's own generation time against the local clock is the
    /// only freshness signal there is. Setting this to zero refuses every head, which is
    /// a way to say the check is not wanted only if the caller means it.
    #[must_use]
    pub fn with_max_head_age(mut self, seconds: u32) -> Config {
        self.max_head_age = seconds;
        self
    }

    /// How far behind the local clock a proven head may be, in seconds.
    #[must_use]
    pub fn max_head_age(&self) -> u32 {
        self.max_head_age
    }

    /// The parsed liteservers, in config order.
    pub(crate) fn liteservers(&self) -> &[LiteServer] {
        &self.liteservers
    }
}

/// Decodes a 32-byte hash from the base64 the config format writes it in.
fn hash(encoded: &str, what: &'static str) -> Result<[u8; 32], Error> {
    base64_decode(encoded)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Config(format!("{what} is not 32 base64 bytes")))
}

#[derive(Deserialize)]
struct RawConfig {
    liteservers: Vec<RawLiteServer>,
    validator: Option<RawValidator>,
}

#[derive(Deserialize)]
struct RawValidator {
    init_block: Option<RawBlockId>,
}

#[derive(Deserialize)]
struct RawBlockId {
    workchain: i32,
    /// Written as a signed 64-bit integer, so the masterchain shard arrives negative.
    shard: i64,
    seqno: u32,
    root_hash: String,
    file_hash: String,
}

#[derive(Deserialize)]
struct RawLiteServer {
    ip: i64,
    port: u16,
    id: RawId,
}

#[derive(Deserialize)]
struct RawId {
    #[serde(rename = "@type")]
    key_type: String,
    key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const KEY: &str = "n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=";

    #[test]
    fn mainnet_parses_and_leads_with_the_proven_server() {
        let config = Config::mainnet();
        assert!(!config.liteservers().is_empty());
        assert_eq!(config.liteservers()[0].addr, "5.9.10.47:19949");
    }

    #[test]
    fn mainnet_names_the_block_a_first_sync_starts_from() {
        // The one input a verified read rests on, so it is worth pinning here rather than
        // trusting whatever the bundled file happens to say. These are the values the
        // public mainnet config published on 2026-07-21.
        let config = Config::mainnet();
        let init = config
            .init_block()
            .expect("the snapshot names an init block");
        assert_eq!(init.workchain, -1);
        assert_eq!(init.shard, 0x8000_0000_0000_0000);
        assert_eq!(init.seqno, 46_894_135);
        assert_eq!(
            hex(&init.root_hash),
            "3048e69a12cf946ebc99b4cf9ca61c3ff4b3fcc88c4015763ac01204ecc1bf9f"
        );
        assert_eq!(
            hex(&init.file_hash),
            "bbdac0b4543e9141449ceb37c3c63ba6e9cc4e2c904d77f56d17e44acf1d1bed"
        );
    }

    #[test]
    fn the_freshness_bound_has_a_default_and_can_be_set() {
        let config = Config::mainnet();
        assert_eq!(config.max_head_age(), DEFAULT_MAX_HEAD_AGE);
        assert_eq!(config.with_max_head_age(30).max_head_age(), 30);
    }

    #[test]
    fn from_json_reads_an_init_block() {
        // The shard arrives as a negative signed 64-bit integer in this format, which is
        // the masterchain's prefix mask read as signed.
        let json = format!(
            r#"{{"liteservers":[{{"ip":84478511,"port":19949,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}],
                "validator":{{"init_block":{{"workchain":-1,"shard":-9223372036854775808,"seqno":7,
                "root_hash":"{KEY}","file_hash":"{KEY}"}}}}}}"#
        );
        let config = Config::from_json(&json).unwrap();
        let init = config.init_block().expect("an init block");
        assert_eq!(init.workchain, -1);
        assert_eq!(init.shard, 0x8000_0000_0000_0000);
        assert_eq!(init.seqno, 7);
    }

    #[test]
    fn from_json_accepts_a_config_with_no_init_block() {
        // A caller who brings their own anchor never needs one, so this parses and the
        // absence surfaces later, at the sync that would have needed it.
        let json = format!(
            r#"{{"liteservers":[{{"ip":84478511,"port":19949,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}]}}"#
        );
        assert!(Config::from_json(&json).unwrap().init_block().is_none());
    }

    #[test]
    fn from_json_rejects_an_init_block_hash_that_is_not_32_bytes() {
        let json = format!(
            r#"{{"liteservers":[{{"ip":84478511,"port":19949,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}],
                "validator":{{"init_block":{{"workchain":-1,"shard":-9223372036854775808,"seqno":7,
                "root_hash":"AAAA","file_hash":"{KEY}"}}}}}}"#
        );
        assert!(matches!(Config::from_json(&json), Err(Error::Config(_))));
    }

    #[test]
    fn from_json_reads_a_liteserver() {
        let json = format!(
            r#"{{"liteservers":[{{"ip":84478511,"port":19949,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}]}}"#
        );
        let config = Config::from_json(&json).unwrap();
        assert_eq!(config.liteservers().len(), 1);
        assert_eq!(config.liteservers()[0].addr, "5.9.10.47:19949");
        assert_eq!(
            hex(&config.liteservers()[0].key),
            "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309"
        );
    }

    #[test]
    fn from_json_decodes_a_negative_ip() {
        // 192.168.0.1 is a negative signed int32 in the TON config format.
        let json = format!(
            r#"{{"liteservers":[{{"ip":-1062731775,"port":1,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}]}}"#
        );
        let config = Config::from_json(&json).unwrap();
        assert_eq!(config.liteservers()[0].addr, "192.168.0.1:1");
    }

    #[test]
    fn from_json_ignores_the_other_config_sections() {
        // The real global.config.json carries dht, validator, and per-server fields this
        // release does not read. Parsing must ignore them, not fail on them.
        let json = format!(
            r#"{{"@type":"config.global","dht":{{"k":1}},"liteservers":[{{"ip":84478511,"port":19949,"extra":true,"id":{{"@type":"pub.ed25519","key":"{KEY}"}}}}],"validator":{{"zero_state":{{"workchain":-1}}}}}}"#
        );
        let config = Config::from_json(&json).unwrap();
        assert_eq!(config.liteservers().len(), 1);
        assert_eq!(config.liteservers()[0].addr, "5.9.10.47:19949");
    }

    #[test]
    fn from_json_rejects_an_unsupported_key_type() {
        let json = format!(
            r#"{{"liteservers":[{{"ip":84478511,"port":19949,"id":{{"@type":"pub.unknown","key":"{KEY}"}}}}]}}"#
        );
        assert!(matches!(Config::from_json(&json), Err(Error::Config(_))));
    }

    #[test]
    fn from_json_rejects_malformed_json() {
        assert!(matches!(
            Config::from_json("{not json"),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn from_json_rejects_an_empty_liteserver_list() {
        assert!(matches!(
            Config::from_json(r#"{"liteservers":[]}"#),
            Err(Error::Config(_))
        ));
    }
}
