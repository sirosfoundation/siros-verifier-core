//! JSON parsing that refuses repeated member names.
//!
//! `serde_json` keeps the last of a repeated key and says nothing, so two readers can disagree about which value
//! a document carries, and the one that is chosen is the sender's decision, not the verifier's. Everything
//! attacker-controlled is parsed here instead. Names are compared after unescaping, so `"a"` and `"\u0061"` count
//! as the same name. Nesting is limited by serde_json's own recursion limit.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::{Error, Result};

/// Walks a document and fails on a repeated member name. It builds nothing, so the value a caller receives is the
/// one serde_json itself produced, whatever number representation the build uses.
struct NoRepeats;

struct NoRepeatsVisitor;

impl<'de> Visitor<'de> for NoRepeatsVisitor {
    type Value = NoRepeats;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_unit<E>(self) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_none<E>(self) -> std::result::Result<NoRepeats, E> {
        Ok(NoRepeats)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<NoRepeats, A::Error> {
        while seq.next_element::<NoRepeats>()?.is_some() {}
        Ok(NoRepeats)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<NoRepeats, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate member name {key:?}")));
            }
            map.next_value::<NoRepeats>()?;
        }
        Ok(NoRepeats)
    }
}

impl<'de> Deserialize<'de> for NoRepeats {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(NoRepeatsVisitor)
    }
}

/// Parse exactly one JSON value from `bytes`, refusing repeated member names and trailing content.
pub fn from_slice(bytes: &[u8]) -> Result<Value> {
    let fail = |e: serde_json::Error| {
        let m = e.to_string();
        if m.contains("duplicate member name") {
            Error::Malformed(format!("json_duplicate_member: {m}"))
        } else {
            Error::Malformed(format!("json: {m}"))
        }
    };
    let value: Value = serde_json::from_slice(bytes).map_err(fail)?;
    serde_json::from_slice::<NoRepeats>(bytes).map_err(fail)?;
    Ok(value)
}

pub fn from_str(s: &str) -> Result<Value> {
    from_slice(s.as_bytes())
}
