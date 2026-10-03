//! Lowercase hex encoding for byte fields on the JSON wire.
//!
//! Traceability: RFC-002 §5 (byte fields are lowercase hex strings, never
//! JSON arrays of numbers — an auditor must be able to grep a hash).
//!
//! Hand-rolled (~40 lines) rather than a dependency: the encoding is part
//! of the wire contract and must not drift with a third-party crate.

use core::fmt;

use serde::{Deserialize, Deserializer, Serializer};

const ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(ALPHABET[(b >> 4) as usize] as char);
        s.push(ALPHABET[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode lowercase or uppercase hex. Rejects odd length and non-hex bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let nibble = |c: u8| -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(HexError::InvalidChar(c as char)),
        }
    };
    bytes
        .chunks_exact(2)
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Hex decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// Input length is not even.
    OddLength,
    /// A byte outside `[0-9a-fA-F]`.
    InvalidChar(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::OddLength => f.write_str("hex string has odd length"),
            HexError::InvalidChar(c) => write!(f, "invalid hex character {c:?}"),
        }
    }
}

impl std::error::Error for HexError {}

/// `#[serde(with = "hex::array32")]` for `[u8; 32]` fields.
pub mod array32 {
    use super::*;

    /// Serialize a 32-byte array as a 64-char lowercase hex string.
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }

    /// Deserialize a 64-char hex string into a 32-byte array.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = decode(&s).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(v)
            .map_err(|v| serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len())))
    }
}

/// `#[serde(with = "hex::vec")]` for `Vec<u8>` fields.
pub mod vec {
    use super::*;

    /// Serialize bytes as lowercase hex.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }

    /// Deserialize hex into bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejections() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode("00abff").map_err(|e| e.to_string()), Ok(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode("00ABFF").map_err(|e| e.to_string()), Ok(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::InvalidChar('z')));
    }
}
