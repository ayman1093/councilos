//! Canonical state model and the M0 hashing rule.
//!
//! Traceability: handover doc §2 ("التسلسل", "الهاش", "الحتمية"), §4-ب; ADR-0001.
//!
//! Invariants:
//! - [`CanonicalValue`] has **no float variant**. Floats cannot enter hashable
//!   state; JSON input containing a float is rejected at deserialization.
//! - Maps are `BTreeMap<String, _>` — keys are emitted in bytewise-sorted order.
//! - The **only** hash preimage in M0 is [`CanonicalValue::to_canonical_json`],
//!   never serde's struct-field ordering. Every hashable type converts itself to
//!   a `CanonicalValue` first (see `Instruction::to_canonical`, `Event::to_canonical`).
//! - Hash layout is `[schema_version: u8][alg: u8][digest: 32B]`, printable as
//!   68 hex characters. The `schema_version || alg` prefix is also fed into the
//!   hash function **before** the canonical bytes, so a digest can never be
//!   mistaken for one produced under another schema or algorithm.
//! - Map keys starting with `$` are reserved for the encoder (`{"$bytes": hex}`)
//!   and are rejected in user maps.
//!
//! Known limitation (documented, M1 backlog — independent-review finding):
//! direct construction of `CanonicalValue::Map` can bypass the `$`-key rule.
//! Resolution (recursive validation at the canonical boundary, or a checked
//! constructor as the only path) is scheduled with ADR-0002.

use core::fmt;
use std::collections::BTreeMap;

use serde::{
    de, ser::SerializeMap, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer,
};

use crate::hex;
use crate::Hash32;

/// Key used to encode [`CanonicalValue::Bytes`] as a single-entry JSON object.
pub const BYTES_TAG: &str = "$bytes";

/// Errors raised while building or hashing canonical values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// JSON contained a floating-point number (forbidden by ADR-0001).
    FloatNotAllowed,
    /// Integer outside `i64` range.
    IntegerOutOfRange,
    /// Map key begins with the reserved `$` prefix.
    ReservedKey(String),
    /// `{"$bytes": ...}` object whose value is not valid hex.
    InvalidBytes(String),
    /// The requested algorithm is declared (ADR-0001) but not linked in M0.
    UnsupportedAlg(HashAlg),
    /// `Instruction::args` must be a map; got another canonical value.
    ArgsMustBeMap,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::FloatNotAllowed => write!(
                f,
                "floating-point numbers are not allowed in canonical state"
            ),
            CanonicalError::IntegerOutOfRange => write!(f, "integer does not fit in i64"),
            CanonicalError::ReservedKey(k) => {
                write!(f, "map key {k:?} uses the reserved '$' prefix")
            }
            CanonicalError::InvalidBytes(e) => write!(f, "invalid $bytes payload: {e}"),
            CanonicalError::UnsupportedAlg(a) => write!(
                f,
                "hash algorithm {a:?} is reserved but not available in M0"
            ),
            CanonicalError::ArgsMustBeMap => {
                write!(f, "instruction args must be a canonical map")
            }
        }
    }
}

impl std::error::Error for CanonicalError {}

/// The closed universe of values that may appear in hashable state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanonicalValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// Signed 64-bit integer. Budgets use milli-units as integers (no floats).
    Int(i64),
    /// Raw bytes; encoded on the wire as `{"$bytes":"<lowercase hex>"}`.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    Str(String),
    /// Ordered sequence.
    Seq(Vec<CanonicalValue>),
    /// Map with bytewise-sorted keys. Keys must not start with `$`.
    Map(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    /// Convenience constructor for a map, validating the reserved-key rule.
    pub fn map<I, K>(entries: I) -> Result<Self, CanonicalError>
    where
        I: IntoIterator<Item = (K, CanonicalValue)>,
        K: Into<String>,
    {
        let mut m = BTreeMap::new();
        for (k, v) in entries {
            let k: String = k.into();
            if k.starts_with('$') {
                return Err(CanonicalError::ReservedKey(k));
            }
            m.insert(k, v);
        }
        Ok(CanonicalValue::Map(m))
    }

    /// Append the compact canonical JSON encoding of `self` to `out`.
    ///
    /// Rules (ADR-0001, schema 0): no whitespace; object keys in bytewise order
    /// (guaranteed by `BTreeMap<String, _>`); integers in shortest decimal form;
    /// strings escaped exactly as `serde_json` escapes them (only `"`, `\`,
    /// control characters); bytes as `{"$bytes":"hex"}`.
    pub fn write_canonical_json(&self, out: &mut String) {
        match self {
            CanonicalValue::Null => out.push_str("null"),
            CanonicalValue::Bool(true) => out.push_str("true"),
            CanonicalValue::Bool(false) => out.push_str("false"),
            CanonicalValue::Int(i) => out.push_str(&i.to_string()),
            CanonicalValue::Bytes(b) => {
                out.push_str("{\"");
                out.push_str(BYTES_TAG);
                out.push_str("\":\"");
                out.push_str(&hex::encode(b));
                out.push_str("\"}");
            }
            CanonicalValue::Str(s) => write_json_string(s, out),
            CanonicalValue::Seq(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical_json(out);
                }
                out.push(']');
            }
            CanonicalValue::Map(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_canonical_json(out);
                }
                out.push('}');
            }
        }
    }

    /// Return the canonical JSON encoding as an owned string.
    pub fn to_canonical_json(&self) -> String {
        let mut s = String::new();
        self.write_canonical_json(&mut s);
        s
    }

    /// Hash this value under `alg` with the M0 schema version.
    pub fn hash(&self, alg: HashAlg) -> Result<StateHash, CanonicalError> {
        StateHash::compute(
            crate::SCHEMA_VERSION,
            alg,
            self.to_canonical_json().as_bytes(),
        )
    }
}

/// JSON-escape a string using serde_json's exact escaping rules.
fn write_json_string(s: &str, out: &mut String) {
    // serde_json::to_string on a &str cannot fail in practice; `unreachable!`
    // (rather than a silent empty-string fallback) so a preimage can never
    // be corrupted silently (independent-review finding).
    match serde_json::to_string(s) {
        Ok(q) => out.push_str(&q),
        Err(e) => unreachable!("serializing a Rust str to JSON cannot fail: {e}"),
    }
}

impl Serialize for CanonicalValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CanonicalValue::Null => s.serialize_unit(),
            CanonicalValue::Bool(b) => s.serialize_bool(*b),
            CanonicalValue::Int(i) => s.serialize_i64(*i),
            CanonicalValue::Bytes(b) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry(BYTES_TAG, &hex::encode(b))?;
                m.end()
            }
            CanonicalValue::Str(v) => s.serialize_str(v),
            CanonicalValue::Seq(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for it in items {
                    seq.serialize_element(it)?;
                }
                seq.end()
            }
            CanonicalValue::Map(map) => {
                let mut m = s.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

impl TryFrom<serde_json::Value> for CanonicalValue {
    type Error = CanonicalError;

    fn try_from(v: serde_json::Value) -> Result<Self, CanonicalError> {
        use serde_json::Value;
        match v {
            Value::Null => Ok(CanonicalValue::Null),
            Value::Bool(b) => Ok(CanonicalValue::Bool(b)),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(CanonicalValue::Int(i))
                } else if n.is_u64() {
                    Err(CanonicalError::IntegerOutOfRange)
                } else {
                    Err(CanonicalError::FloatNotAllowed)
                }
            }
            Value::String(s) => Ok(CanonicalValue::Str(s)),
            Value::Array(items) => items
                .into_iter()
                .map(CanonicalValue::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map(CanonicalValue::Seq),
            Value::Object(obj) => {
                // `{"$bytes": "hex"}` is the encoder's representation of Bytes.
                if obj.len() == 1 {
                    if let Some(Value::String(h)) = obj.get(BYTES_TAG) {
                        return hex::decode(h)
                            .map(CanonicalValue::Bytes)
                            .map_err(|e| CanonicalError::InvalidBytes(e.to_string()));
                    }
                }
                let mut m = BTreeMap::new();
                for (k, v) in obj {
                    if k.starts_with('$') {
                        return Err(CanonicalError::ReservedKey(k));
                    }
                    m.insert(k, CanonicalValue::try_from(v)?);
                }
                Ok(CanonicalValue::Map(m))
            }
        }
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(d)?;
        CanonicalValue::try_from(raw).map_err(de::Error::custom)
    }
}

/// Top-level session state: a sorted map from key to canonical value.
pub type CanonicalState = BTreeMap<String, CanonicalValue>;

/// Canonicalize a whole state (wraps it as a [`CanonicalValue::Map`]).
///
/// Returns an error if any top-level key uses the reserved `$` prefix.
pub fn canonical(state: &CanonicalState) -> Result<CanonicalValue, CanonicalError> {
    CanonicalValue::map(state.iter().map(|(k, v)| (k.clone(), v.clone())))
}

/// Hash algorithm identifiers (ADR-0001). The numeric value is the on-wire byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum HashAlg {
    /// BLAKE3, 32-byte output. Default for all M0/M1 hashes.
    Blake3 = 0x01,
    /// SHA-256. Reserved for FIPS-constrained clients; not linked in M0.
    Sha256 = 0x02,
}

impl HashAlg {
    /// The single byte written after `schema_version` in every hash.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse an algorithm id byte.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(HashAlg::Blake3),
            0x02 => Some(HashAlg::Sha256),
            _ => None,
        }
    }
}

/// A versioned, algorithm-tagged digest: `[schema_version][alg][digest; 32]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateHash {
    /// Canonical serialization schema the preimage was produced under.
    pub schema_version: u8,
    /// Hash algorithm used.
    pub alg: HashAlg,
    /// The 32-byte digest.
    pub digest: Hash32,
}

impl StateHash {
    /// Total encoded length in bytes: 1 + 1 + 32.
    pub const LEN: usize = 34;

    /// Compute `alg( [schema_version][alg] || preimage )`.
    ///
    /// Prefixing the preimage with the two header bytes binds the digest to its
    /// declared version and algorithm (domain separation).
    pub fn compute(
        schema_version: u8,
        alg: HashAlg,
        preimage: &[u8],
    ) -> Result<Self, CanonicalError> {
        match alg {
            HashAlg::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&[schema_version, alg.id()]);
                hasher.update(preimage);
                Ok(StateHash {
                    schema_version,
                    alg,
                    digest: *hasher.finalize().as_bytes(),
                })
            }
            HashAlg::Sha256 => Err(CanonicalError::UnsupportedAlg(alg)),
        }
    }

    /// Encode as 34 bytes.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.schema_version;
        out[1] = self.alg.id();
        out[2..].copy_from_slice(&self.digest);
        out
    }

    /// Decode from 34 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let alg = HashAlg::from_id(bytes[1])?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[2..]);
        Some(StateHash {
            schema_version: bytes[0],
            alg,
            digest,
        })
    }

    /// 68-character lowercase hex of [`Self::to_bytes`].
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    /// Parse the 68-character hex form.
    pub fn from_hex(text: &str) -> Option<Self> {
        hex::decode(text).ok().and_then(|b| Self::from_bytes(&b[..]))
    }
}

impl fmt::Display for StateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for StateHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for StateHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        StateHash::from_hex(&text)
            .ok_or_else(|| de::Error::custom("expected 68 hex chars: [schema][alg][digest32]"))
    }
}

/// One link in the state chain produced after applying event `sequence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRecord {
    /// Sequence of the [`crate::Event`] that produced this state.
    pub sequence: u64,
    /// Hash of the canonical state after the event.
    pub state_hash: StateHash,
    /// Hash of the previous record's state; `None` only for the genesis record.
    pub prev_hash: Option<StateHash>,
}

impl StateRecord {
    /// Build the record for `state` following `prev` (or genesis when `None`).
    pub fn new(
        sequence: u64,
        state: &CanonicalState,
        prev: Option<&StateRecord>,
        alg: HashAlg,
    ) -> Result<Self, CanonicalError> {
        let state_hash = canonical(state)?.hash(alg)?;
        Ok(StateRecord {
            sequence,
            state_hash,
            prev_hash: prev.map(|p| p.state_hash),
        })
    }

    /// Canonical form of the record itself (for chaining/audit in M1).
    pub fn to_canonical(&self) -> CanonicalValue {
        let mut m = BTreeMap::new();
        m.insert(
            "sequence".to_string(),
            CanonicalValue::Int(self.sequence as i64),
        );
        m.insert(
            "state_hash".to_string(),
            CanonicalValue::Bytes(self.state_hash.to_bytes().to_vec()),
        );
        m.insert(
            "prev_hash".to_string(),
            match self.prev_hash {
                Some(h) => CanonicalValue::Bytes(h.to_bytes().to_vec()),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CanonicalValue {
        let mut m = BTreeMap::new();
        m.insert("z".to_string(), CanonicalValue::Int(-1));
        m.insert("a".to_string(), CanonicalValue::Str("x\"y".to_string()));
        m.insert("b".to_string(), CanonicalValue::Bytes(vec![0xde, 0xad]));
        m.insert(
            "s".to_string(),
            CanonicalValue::Seq(vec![CanonicalValue::Null, CanonicalValue::Bool(true)]),
        );
        CanonicalValue::Map(m)
    }

    #[test]
    fn canonical_json_is_sorted_compact_and_stable() {
        assert_eq!(
            sample().to_canonical_json(),
            r#"{"a":"x\"y","b":{"$bytes":"dead"},"s":[null,true],"z":-1}"#
        );
    }

    #[test]
    fn wire_json_roundtrips_to_identical_canonical_value() {
        let v = sample();
        let wire = serde_json::to_string(&v).map_err(|e| e.to_string());
        let back: Result<CanonicalValue, String> =
            wire.and_then(|w| serde_json::from_str(&w).map_err(|e| e.to_string()));
        assert_eq!(back, Ok(v));
    }

    #[test]
    fn floats_are_rejected_on_input() {
        let r: Result<CanonicalValue, _> = serde_json::from_str("{\"x\": 1.5}");
        assert!(r.is_err());
        let r: Result<CanonicalValue, _> = serde_json::from_str("[1e3]");
        assert!(r.is_err());
    }

    #[test]
    fn reserved_keys_are_rejected() {
        assert_eq!(
            CanonicalValue::map([("$evil", CanonicalValue::Null)]),
            Err(CanonicalError::ReservedKey("$evil".to_string()))
        );
        let r: Result<CanonicalValue, _> = serde_json::from_str("{\"$bytes\":\"zz\"}");
        assert!(r.is_err());
        let r: Result<CanonicalValue, _> = serde_json::from_str("{\"$other\":1}");
        assert!(r.is_err());
    }

    #[test]
    fn hash_layout_is_version_alg_digest() {
        let h = match sample().hash(HashAlg::Blake3) {
            Ok(h) => h,
            Err(e) => panic!("blake3 must be available: {e}"),
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes[0], crate::SCHEMA_VERSION);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(h.to_hex().len(), 68);
        assert_eq!(StateHash::from_hex(&h.to_hex()), Some(h));
    }

    #[test]
    fn header_bytes_are_part_of_the_preimage() {
        let plain = blake3::hash(sample().to_canonical_json().as_bytes());
        let ours = sample().hash(HashAlg::Blake3).map(|h| h.digest);
        assert_ne!(ours, Ok(*plain.as_bytes()));
    }

    #[test]
    fn sha256_is_reserved_not_available() {
        assert_eq!(
            sample().hash(HashAlg::Sha256),
            Err(CanonicalError::UnsupportedAlg(HashAlg::Sha256))
        );
    }

    #[test]
    fn state_record_chains_prev_hash() {
        let mut s: CanonicalState = BTreeMap::new();
        s.insert("counter".into(), CanonicalValue::Int(0));
        let genesis = match StateRecord::new(0, &s, None, HashAlg::Blake3) {
            Ok(g) => g,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(genesis.prev_hash, None);
        s.insert("counter".into(), CanonicalValue::Int(1));
        let next = match StateRecord::new(1, &s, Some(&genesis), HashAlg::Blake3) {
            Ok(n) => n,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(next.prev_hash, Some(genesis.state_hash));
        assert_ne!(next.state_hash, genesis.state_hash);
    }
    }
