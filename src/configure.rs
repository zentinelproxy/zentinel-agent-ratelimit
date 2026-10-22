//! Helpers for applying the proxy's `config { }` block.
//!
//! The proxy sends the block on every connection (each pooled connection and
//! every reconnect), so applying it must be idempotent: the same block twice
//! changes nothing, and a block only overlays the settings the agent was
//! started with.

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// `value` with every object's keys sorted, so equal configs serialize equally.
pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// A stable hash (FNV-1a, 64 bit) of the canonical JSON of `value`.
///
/// Stable across processes and builds, so it can be compared in logs.
pub fn canonical_hash(value: &Value) -> String {
    let text = serialize_sorted(value);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Serialize with object keys sorted, independent of serde_json's map order.
fn serialize_sorted(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), serialize_sorted(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(serialize_sorted).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

/// Overlay `patch` onto `base`: objects merge key by key (recursively), any
/// other value in `patch` replaces the one in `base`.
pub fn overlay(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            for (k, v) in patch_map {
                match base_map.get_mut(k) {
                    Some(existing) if existing.is_object() && v.is_object() => overlay(existing, v),
                    _ => {
                        base_map.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (base, patch) => *base = patch.clone(),
    }
}

/// Dotted paths of the settings that differ between `old` and `new`.
pub fn changed_keys(old: &Value, new: &Value) -> Vec<String> {
    let mut out = Vec::new();
    diff(old, new, "", &mut out);
    out.sort();
    out
}

fn diff(old: &Value, new: &Value, prefix: &str, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => diff(x, y, &path, out),
                    _ => out.push(path),
                }
            }
        }
        (a, b) if a == b => {}
        _ => out.push(if prefix.is_empty() {
            "<root>".to_string()
        } else {
            prefix.to_string()
        }),
    }
}

/// Deserialize a list that may also arrive as a single value.
///
/// The proxy turns a KDL node with one argument into a scalar, so a one-item
/// list arrives as that item rather than as an array.
pub fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    match Value::deserialize(deserializer)? {
        Value::Array(items) => items
            .into_iter()
            .map(|v| serde_json::from_value(v).map_err(D::Error::custom))
            .collect(),
        single => Ok(vec![
            serde_json::from_value(single).map_err(D::Error::custom)?
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_ignores_key_order() {
        let a = json!({"a": 1, "b": {"x": [1, 2], "y": true}});
        let b: Value = serde_json::from_str(r#"{"b": {"y": true, "x": [1, 2]}, "a": 1}"#).unwrap();
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
        assert_ne!(canonical_hash(&a), canonical_hash(&json!({"a": 2})));
        assert_eq!(canonical(&a), canonical(&b));
    }

    #[test]
    fn overlay_keeps_absent_fields() {
        let mut base = json!({"a": 1, "nested": {"x": 1, "y": 2}, "list": [1, 2]});
        overlay(&mut base, &json!({"nested": {"y": 3}, "list": [9]}));
        assert_eq!(
            base,
            json!({"a": 1, "nested": {"x": 1, "y": 3}, "list": [9]})
        );
    }

    #[test]
    fn changed_keys_lists_paths() {
        let old = json!({"a": 1, "n": {"x": 1, "y": 2}});
        let new = json!({"a": 1, "n": {"x": 1, "y": 3}, "b": true});
        assert_eq!(changed_keys(&old, &new), vec!["b", "n.y"]);
    }
}
