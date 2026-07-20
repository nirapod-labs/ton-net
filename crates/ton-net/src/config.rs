//! The network config: the liteservers a client can reach.

use serde::Deserialize;

use crate::codec::base64_decode;
use crate::Error;

/// The public network parameters a client needs to reach TON.
///
/// A config lists the liteservers to connect to. It holds only public data and never a
/// secret. Later releases carry the DHT seed nodes and init block a config also names;
/// this release reads the liteserver list.
#[derive(Debug, Clone)]
pub struct Config {
    liteservers: Vec<LiteServer>,
}

/// One liteserver: an address ready to dial and its public key.
#[derive(Debug, Clone)]
pub(crate) struct LiteServer {
    pub(crate) addr: String,
    pub(crate) key: [u8; 32],
}

impl Config {
    /// Returns a config for TON mainnet from a bundled snapshot.
    ///
    /// The snapshot is a point-in-time copy of the public mainnet config and can go stale
    /// as liteservers rotate. To use a current config, fetch `global.config.json` and pass
    /// it to [`Config::from_json`].
    #[must_use]
    pub fn mainnet() -> Config {
        // The bundled snapshot is checked in and parsed at build of the caller; it is
        // valid by construction and covered by a test.
        Config::from_json(include_str!("mainnet.config.json"))
            .expect("the bundled mainnet config parses")
    }

    /// Parses a config from the TON `global.config.json` format.
    ///
    /// Only the liteserver list is read; other sections are ignored. Each liteserver's
    /// `ip` is a signed 32-bit integer in that format, decoded here to dotted-quad form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the JSON is malformed, has no liteserver list, or a
    /// liteserver has an unsupported key type or a key that is not 32 bytes.
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
        Ok(Config { liteservers })
    }

    /// The parsed liteservers, in config order.
    pub(crate) fn liteservers(&self) -> &[LiteServer] {
        &self.liteservers
    }
}

#[derive(Deserialize)]
struct RawConfig {
    liteservers: Vec<RawLiteServer>,
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
