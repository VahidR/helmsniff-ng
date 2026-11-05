//! YAML loading for multi-document Kubernetes manifest files.
//!
//! Produces untyped `Mapping` trees suitable for the scanner's checks. The
//! loader mirrors the behaviour of Go's `yaml.v3` decoding into
//! `map[string]interface{}` so that both implementations report identical rows:
//!
//! - empty documents (`---` separators, comment-only blocks) are skipped
//! - a document whose root is not a mapping (scalar, list) is an error
//! - scalar mapping keys (`1:`, `true:`) are coerced to strings
//! - `<<` merge keys are expanded
//! - a duplicate key within one mapping is an error

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;

/// One parsed YAML document with string keys.
pub type Doc = Mapping;

/// Errors produced while loading YAML documents.
#[derive(Debug)]
pub enum ParseError {
    /// The file could not be opened or read.
    Io(std::io::Error),
    /// The YAML is malformed (syntax error, duplicate key, bad merge).
    Yaml(serde_yaml_ng::Error),
    /// A document's root node is not a mapping.
    NotAMapping,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "{e}"),
            ParseError::Yaml(e) => write!(f, "yaml: {e}"),
            ParseError::NotAMapping => write!(f, "yaml: cannot unmarshal non-mapping document"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl From<serde_yaml_ng::Error> for ParseError {
    fn from(e: serde_yaml_ng::Error) -> Self {
        ParseError::Yaml(e)
    }
}

/// Reads a multi-document YAML file and returns each non-empty document.
///
/// Returns an error if the file cannot be opened or contains malformed YAML.
pub fn load_yaml_docs(path: impl AsRef<Path>) -> Result<Vec<Doc>, ParseError> {
    let f = File::open(path)?;
    load_yaml_docs_from_reader(f)
}

/// Reads multi-document YAML from any reader (file, stdin) and returns each
/// non-empty document as a mapping. See the module docs for the exact rules.
pub fn load_yaml_docs_from_reader<R: Read>(r: R) -> Result<Vec<Doc>, ParseError> {
    let mut out = Vec::new();
    for de in serde_yaml_ng::Deserializer::from_reader(r) {
        let mut value = Value::deserialize(de)?;
        value.apply_merge()?;
        match normalize(value) {
            Value::Null => continue,
            Value::Mapping(m) if m.is_empty() => continue,
            Value::Mapping(m) => out.push(m),
            _ => return Err(ParseError::NotAMapping),
        }
    }
    Ok(out)
}

/// Recursively rewrites a value tree to match `yaml.v3` decoding into Go maps:
/// scalar keys become strings and explicitly tagged scalars lose their tag.
/// Non-scalar keys (lists, maps) are left untouched; the checks never look
/// them up by name, so they cannot change a result.
fn normalize(v: Value) -> Value {
    match v {
        Value::Mapping(m) => {
            let mut out = Mapping::with_capacity(m.len());
            for (k, v) in m {
                let k = match k {
                    Value::Number(n) => Value::String(n.to_string()),
                    Value::Bool(b) => Value::String(b.to_string()),
                    other => other,
                };
                out.insert(k, normalize(v));
            }
            Value::Mapping(out)
        }
        Value::Sequence(s) => Value::Sequence(s.into_iter().map(normalize).collect()),
        Value::Tagged(t) => normalize(t.value),
        other => other,
    }
}
