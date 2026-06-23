//! JCS-style canonicalization matching `attestix/auth/crypto.py::canonicalize_json`.
//!
//! This is **NOT** strict RFC 8785. The two load-bearing divergences:
//!
//! 1. **NFC normalization** - every string value and every object key is
//!    Unicode-NFC-normalized before serialization. RFC 8785 does *not* normalize.
//! 2. **Number formatting** - whole-number floats collapse to integers
//!    (`1.0` -> `1`); other numbers are emitted from their literal token. Large
//!    integers (`> 2^53`) keep full precision.
//!
//! The output is the byte string produced by Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! after the recursive `_normalize_for_signing` pass, encoded UTF-8.

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

/// Produce the Attestix JCS-style canonical UTF-8 bytes for a JSON value.
///
/// The result must match the conformance vectors' `canonical_bytes_hex`
/// byte-for-byte.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(value, &mut out);
    out.into_bytes()
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(&n.to_string(), out),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // NFC-normalize keys, then sort by Unicode code point.
            // For valid UTF-8, byte order == code-point order, but we sort on
            // the Rust `String` which compares by `char` (code point) directly.
            let mut entries: Vec<(String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.nfc().collect::<String>(), v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

/// Serialize a number from its raw JSON token (requires serde_json
/// `arbitrary_precision`, which exposes the literal token via `as_str`).
///
/// Mirrors Python's `_normalize_for_signing`:
/// - integer tokens (no `.`, `e`, `E`) are emitted verbatim - big ints keep
///   full precision;
/// - whole-number floats (`1.0`, `2.0e0`) collapse to their integer form;
/// - other floats are emitted via their canonical decimal form.
fn write_number(token: &str, out: &mut String) {
    let is_float = token.contains('.') || token.contains('e') || token.contains('E');
    if !is_float {
        // Pure integer token (incl. negatives and values > 2^53). Verbatim.
        out.push_str(token);
        return;
    }
    // Float token. Decide whole vs non-whole by parsing as f64.
    // The Attestix canonical form only signs integers and simple decimals such
    // as 1.5; non-whole floats inherit Python's repr, which agrees with Rust's
    // shortest round-trip formatting for these trivial values.
    match token.parse::<f64>() {
        Ok(f) if f.is_finite() && f == f.trunc() && !(f == 0.0 && token.starts_with('-')) => {
            // Whole number float -> integer (1.0 -> 1). Guard -0.0.
            out.push_str(&format_whole_float(f));
        }
        Ok(f) if f.is_finite() => {
            out.push_str(&format_fraction_float(f));
        }
        _ => {
            // Non-finite or unparseable: fall back to the literal token.
            out.push_str(token);
        }
    }
}

fn format_whole_float(f: f64) -> String {
    // f is whole and finite; render as an integer with no decimal point.
    // f64 whole numbers up to 2^53 are exact; larger whole floats are rare in
    // signed payloads (big ints arrive as integer tokens, handled above).
    (f as i128).to_string()
}

fn format_fraction_float(f: f64) -> String {
    // Shortest round-trip decimal (Rust default), which matches Python repr for
    // the simple decimals used in the conformance vectors (e.g. 1.5).
    f.to_string()
}

/// JSON-escape a string exactly as Python's `json.dumps(..., ensure_ascii=False)`:
/// escape `"`, `\`, and the C0 control characters (`U+0000`..=`U+001F`) using the
/// short forms where Python does (`\b \t \n \f \r`) and `\u00XX` otherwise; emit
/// every other character (including all non-ASCII) as raw UTF-8.
///
/// The input is NFC-normalized here so callers can pass raw values directly.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.nfc() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn whole_float_collapses_to_int() {
        let v: Value = serde_json::from_str(r#"{"a":1.0}"#).unwrap();
        assert_eq!(canonicalize(&v), br#"{"a":1}"#.to_vec());
    }

    #[test]
    fn fraction_float_preserved() {
        let v: Value = serde_json::from_str(r#"{"a":1.5}"#).unwrap();
        assert_eq!(canonicalize(&v), br#"{"a":1.5}"#.to_vec());
    }

    #[test]
    fn big_int_full_precision() {
        let v: Value = serde_json::from_str(r#"{"a":9007199254740993}"#).unwrap();
        assert_eq!(canonicalize(&v), br#"{"a":9007199254740993}"#.to_vec());
    }

    #[test]
    fn keys_sorted_by_codepoint() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&v), br#"{"a":2,"b":1}"#.to_vec());
    }
}
