//! Deliberately bounded JSON structural subset. Unknown keywords are rejected.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_types_bounds_and_raw_bytes() {
        let p: Policy=serde_json::from_value(serde_json::json!({"schema":{"type":"object","required":["name","tags"],"properties":{"name":{"type":"string","minLength":1,"maxLength":4},"tags":{"type":"array","maxItems":2,"items":{"type":"integer"}}},"additionalProperties":false}})).unwrap();
        p.validate().unwrap();
        let raw = br#"{ "name":"ok", "tags":[1,2] }"#;
        let original = raw.to_vec();
        assert_eq!(p.check(Some("application/json"), raw), Outcome::Valid);
        assert_eq!(raw, original.as_slice());
        for raw in [
            br#"{}"#.as_slice(),
            br#"{"name":"abcde","tags":[]}"#,
            br#"{"name":"ok","tags":["x"]}"#,
            br#"{"name":"ok","tags":[1,2,3]}"#,
            br#"{"name":"ok","tags":[],"extra":1}"#,
        ] {
            assert_eq!(p.check(Some("application/json"), raw), Outcome::Invalid);
        }
        assert_eq!(
            p.check(Some("multipart/form-data"), raw),
            Outcome::ContentType
        );
        assert_eq!(
            p.check(Some("application/json"), &vec![b' '; 65537]),
            Outcome::OverBudget
        );
        assert!(
            serde_json::from_value::<Policy>(
                serde_json::json!({"schema":{"type":"object","$ref":"#/foo"}})
            )
            .is_err()
        );
    }
    #[test]
    fn depth_and_cross_type_keywords_rejected() {
        let mut schema = serde_json::json!({"type":"string"});
        for _ in 0..10 {
            schema = serde_json::json!({"type":"array","items":schema});
        }
        let p: Policy = serde_json::from_value(serde_json::json!({"schema":schema})).unwrap();
        assert!(p.validate().is_err());
        let p: Policy =
            serde_json::from_value(serde_json::json!({"schema":{"type":"integer","maxLength":3}}))
                .unwrap();
        assert!(p.validate().is_err());
    }
}
use crate::Validation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Block,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    pub schema: Schema,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Type {
    Object,
    Array,
    String,
    Integer,
    Number,
    Boolean,
    Null,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    #[serde(rename = "type")]
    pub kind: Type,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Schema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(
        default,
        rename = "additionalProperties",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<Schema>>,
    #[serde(default, rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(default, rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    #[serde(default, rename = "minItems", skip_serializing_if = "Option::is_none")]
    pub min_items: Option<usize>,
    #[serde(default, rename = "maxItems", skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Valid,
    Invalid,
    ContentType,
    OverBudget,
}
impl Policy {
    pub fn validate(&self) -> Result<(), Validation> {
        self.schema.validate(0, &mut 0)
    }
    pub fn check(&self, content_type: Option<&str>, bytes: &[u8]) -> Outcome {
        if bytes.len() > 65536 {
            return Outcome::OverBudget;
        }
        if content_type.is_none_or(|t| {
            !t.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        }) {
            return Outcome::ContentType;
        }
        let value = match bounded_json(bytes) {
            Ok(v) => v,
            Err(outcome) => return outcome,
        };
        let mut steps = 0;
        let valid = self.schema.matches(&value, 0, &mut steps);
        if steps > 8192 {
            Outcome::OverBudget
        } else if valid {
            Outcome::Valid
        } else {
            Outcome::Invalid
        }
    }
}
impl Schema {
    fn validate(&self, depth: usize, nodes: &mut usize) -> Result<(), Validation> {
        *nodes += 1;
        if depth > 8
            || *nodes > 256
            || self.properties.len() > 64
            || self.required.len() > 64
            || self
                .properties
                .keys()
                .any(|s| s.is_empty() || s.len() > 64 || s.chars().any(char::is_control))
            || self
                .required
                .iter()
                .any(|s| !self.properties.contains_key(s))
            || self
                .required
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.required.len()
            || self.min_length.unwrap_or(0) > self.max_length.unwrap_or(65536)
            || self.max_length.is_some_and(|n| n > 65536)
            || self.min_items.unwrap_or(0) > self.max_items.unwrap_or(1024)
            || self.max_items.is_some_and(|n| n > 1024)
            || self.min_length.is_some_and(|n| n > 65536)
            || self.min_items.is_some_and(|n| n > 1024)
            || (self.kind != Type::Object
                && (!self.properties.is_empty()
                    || !self.required.is_empty()
                    || self.additional.is_some()))
            || (self.kind != Type::Array
                && (self.items.is_some() || self.min_items.is_some() || self.max_items.is_some()))
            || (self.kind == Type::Array && self.items.is_none())
            || (self.kind != Type::String
                && (self.min_length.is_some() || self.max_length.is_some()))
        {
            return Err(Validation::Middleware);
        }
        for child in self.properties.values() {
            child.validate(depth + 1, nodes)?;
        }
        if let Some(child) = &self.items {
            child.validate(depth + 1, nodes)?;
        }
        Ok(())
    }
    fn matches(&self, v: &serde_json::Value, depth: usize, steps: &mut usize) -> bool {
        *steps += 1;
        if depth > 8 || *steps > 8192 {
            return false;
        }
        match self.kind {
            Type::Object => v.as_object().is_some_and(|o| {
                o.len() <= 1024
                    && self.required.iter().all(|k| o.contains_key(k))
                    && o.iter().all(|(k, v)| match self.properties.get(k) {
                        Some(s) => s.matches(v, depth + 1, steps),
                        None => self.additional != Some(false),
                    })
            }),
            Type::Array => v.as_array().is_some_and(|a| {
                a.len() >= self.min_items.unwrap_or(0)
                    && a.len() <= self.max_items.unwrap_or(1024)
                    && self
                        .items
                        .as_ref()
                        .is_some_and(|s| a.iter().all(|v| s.matches(v, depth + 1, steps)))
            }),
            Type::String => v.as_str().is_some_and(|s| {
                let n = s.chars().count();
                n >= self.min_length.unwrap_or(0) && n <= self.max_length.unwrap_or(65536)
            }),
            Type::Integer => v.is_i64() || v.is_u64(),
            Type::Number => v.is_number(),
            Type::Boolean => v.is_boolean(),
            Type::Null => v.is_null(),
        }
    }
}
/// Explicit selection from OpenAPI 3.x. Only the selected operation's required
/// JSON request body is imported. All unsupported schema keywords fail serde;
/// parameters/responses/security are returned as unsupported, never inferred.
pub fn import(
    document: &serde_json::Value,
    path: &str,
    method: &str,
) -> Result<Policy, Validation> {
    if serde_json::to_vec(document)
        .map_err(|_| Validation::Limit)?
        .len()
        > 262144
        || !document["openapi"]
            .as_str()
            .is_some_and(|s| s.starts_with("3.0.") || s.starts_with("3.1."))
        || crate::canonical_path(path)? != path
        || method.parse::<http::Method>().is_err()
        || method != method.to_ascii_uppercase()
    {
        return Err(Validation::Middleware);
    }
    let operation = &document["paths"][path][method.to_ascii_lowercase()];
    let request = &operation["requestBody"];
    let content = request["content"]
        .as_object()
        .ok_or(Validation::Middleware)?;
    if request["required"] != true
        || content.len() != 1
        || !content.contains_key("application/json")
        || request.get("$ref").is_some()
    {
        return Err(Validation::Middleware);
    }
    let schema = serde_json::from_value(content["application/json"]["schema"].clone())
        .map_err(|_| Validation::Middleware)?;
    let policy = Policy {
        mode: Mode::Observe,
        schema,
    };
    policy.validate()?;
    Ok(policy)
}

// Reject duplicate keys and bound the complete input tree, including values
// allowed by additionalProperties. The borrowed input bytes remain untouched.
fn bounded_json(bytes: &[u8]) -> Result<serde_json::Value, Outcome> {
    use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
    struct Seed<'a> {
        depth: usize,
        nodes: &'a mut usize,
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = serde_json::Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            *self.nodes += 1;
            if self.depth > 16 || *self.nodes > 8192 {
                return Err(D::Error::custom("input budget"));
            }
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = serde_json::Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded JSON")
        }
        fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
            serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .ok_or_else(|| E::custom("invalid JSON number"))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(serde_json::Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(v) = a.next_element_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })? {
                if values.len() >= 1024 {
                    return Err(A::Error::custom("input budget"));
                }
                values.push(v);
            }
            Ok(values.into())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut values = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if values.len() >= 1024 {
                    return Err(A::Error::custom("input budget"));
                }
                if values.contains_key(&k) {
                    return Err(A::Error::custom("duplicate JSON key"));
                }
                let v = a.next_value_seed(Seed {
                    depth: self.depth + 1,
                    nodes: self.nodes,
                })?;
                values.insert(k, v);
            }
            Ok(values.into())
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0;
    let value = Seed {
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut decoder)
    .map_err(|e| {
        if e.to_string().starts_with("input budget") {
            Outcome::OverBudget
        } else {
            Outcome::Invalid
        }
    })?;
    decoder.end().map_err(|_| Outcome::Invalid)?;
    Ok(value)
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn duplicates_and_complete_input_budget_are_explicit() {
        let p: Policy =
            serde_json::from_value(serde_json::json!({"schema":{"type":"object"}})).unwrap();
        assert_eq!(
            p.check(Some("application/json"), br#"{"x":1,"x":2}"#),
            Outcome::Invalid
        );
        let deep = format!("{{\"x\":{}0{}}}", "[".repeat(20), "]".repeat(20));
        assert_eq!(
            p.check(Some("application/json"), deep.as_bytes()),
            Outcome::OverBudget
        );
        let wide = format!("{{\"x\":[{}]}}", vec!["0"; 1025].join(","));
        assert_eq!(
            p.check(Some("application/json"), wide.as_bytes()),
            Outcome::OverBudget
        );
    }
    #[test]
    fn openapi_import_is_selected_observe_only_and_rejects_unsupported_keywords() {
        let mut doc = serde_json::json!({"openapi":"3.0.3","paths":{"/items":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":8}}}}}}}}}});
        let p = import(&doc, "/items", "POST").unwrap();
        assert_eq!(p.mode, Mode::Observe);
        p.validate().unwrap();
        assert!(import(&doc, "/items", "post").is_err());
        assert!(import(&doc, "/other", "POST").is_err());
        doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]
            ["name"]["pattern"] = ".*".into();
        assert!(import(&doc, "/items", "POST").is_err());
    }
}
