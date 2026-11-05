//! Tests for the YAML loader. Mirrors the Go `parser_test.go` suite and adds
//! cases for the `yaml.v3` parity rules implemented in `normalize`.

use super::*;
use std::fs;
use std::path::PathBuf;

use serde_yaml_ng::Value;

/// Writes `content` to `<dir>/<name>` and returns the path.
fn write_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).expect("write test file");
    path
}

/// Returns the string value of `key` in `doc`, or "" if absent.
fn kind(doc: &Doc) -> &str {
    doc.get("kind").and_then(Value::as_str).unwrap_or("")
}

/// Loads `input` through the reader entry point.
fn load(input: &str) -> Result<Vec<Doc>, ParseError> {
    load_yaml_docs_from_reader(input.as_bytes())
}

// ---------- load_yaml_docs ----------

#[test]
fn load_yaml_docs_single_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(
        dir.path(),
        "single.yaml",
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  key: value\n",
    );
    let docs = load_yaml_docs(&path).expect("load");
    assert_eq!(docs.len(), 1);
    assert_eq!(kind(&docs[0]), "ConfigMap");
}

#[test]
fn load_yaml_docs_multi_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(
        dir.path(),
        "multi.yaml",
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n",
    );
    let docs = load_yaml_docs(&path).expect("load");
    let kinds: Vec<&str> = docs.iter().map(kind).collect();
    assert_eq!(kinds, ["Service", "Deployment", "ConfigMap"]);
}

#[test]
fn load_yaml_docs_empty_documents_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(
        dir.path(),
        "empty_docs.yaml",
        "---\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n---\n---\n",
    );
    let docs = load_yaml_docs(&path).expect("load");
    assert_eq!(docs.len(), 1, "empty docs should be skipped");
    assert_eq!(kind(&docs[0]), "Pod");
}

#[test]
fn load_yaml_docs_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(dir.path(), "empty.yaml", "");
    assert!(load_yaml_docs(&path).expect("load").is_empty());
}

#[test]
fn load_yaml_docs_only_separators() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(dir.path(), "seps.yaml", "---\n---\n---\n");
    assert!(load_yaml_docs(&path).expect("load").is_empty());
}

#[test]
fn load_yaml_docs_malformed_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(dir.path(), "bad.yaml", "{{{{ not valid yaml");
    assert!(matches!(load_yaml_docs(&path), Err(ParseError::Yaml(_))));
}

#[test]
fn load_yaml_docs_file_not_found() {
    assert!(matches!(
        load_yaml_docs("/nonexistent/path/file.yaml"),
        Err(ParseError::Io(_))
    ));
}

#[test]
fn load_yaml_docs_nested_structure() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(
        dir.path(),
        "nested.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  labels:\n    app: myapp\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:1.21\n        ports:\n        - containerPort: 80\n        env:\n        - name: FOO\n          value: bar\n",
    );
    let docs = load_yaml_docs(&path).expect("load");
    assert_eq!(docs.len(), 1);
    let spec = docs[0]
        .get("spec")
        .and_then(Value::as_mapping)
        .expect("spec is a map");
    assert_eq!(spec.get("replicas").and_then(Value::as_i64), Some(3));
}

#[test]
fn load_yaml_docs_boolean_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(
        dir.path(),
        "bools.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nspec:\n  hostPID: true\n  hostIPC: false\n",
    );
    let docs = load_yaml_docs(&path).expect("load");
    let spec = docs[0].get("spec").and_then(Value::as_mapping).unwrap();
    assert_eq!(spec.get("hostPID"), Some(&Value::Bool(true)));
    assert_eq!(spec.get("hostIPC"), Some(&Value::Bool(false)));
}

#[cfg(unix)]
#[test]
fn load_yaml_docs_permission_denied() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
    {
        eprintln!("skipped: running as root, permission bits are not enforced");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write_test_file(dir.path(), "noperm.yaml", "key: value");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let res = load_yaml_docs(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(res, Err(ParseError::Io(_))));
}

// ---------- load_yaml_docs_from_reader ----------

#[test]
fn from_reader_single_document() {
    let docs =
        load("apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n  type: ClusterIP\n")
            .unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(kind(&docs[0]), "Service");
}

#[test]
fn from_reader_multi_document() {
    let docs = load("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: prod\n---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n").unwrap();
    assert_eq!(docs.len(), 3);
    assert_eq!(kind(&docs[0]), "Namespace");
    assert_eq!(kind(&docs[2]), "NetworkPolicy");
}

#[test]
fn from_reader_empty_input() {
    assert!(load("").unwrap().is_empty());
}

#[test]
fn from_reader_empty_docs_skipped() {
    let docs = load("---\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n---\n").unwrap();
    assert_eq!(docs.len(), 1);
}

#[test]
fn from_reader_malformed_yaml() {
    assert!(matches!(load("{{{{ invalid"), Err(ParseError::Yaml(_))));
}

#[test]
fn from_reader_malformed_after_valid() {
    let res = load("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n---\n{{{{ bad yaml\n");
    assert!(
        res.is_err(),
        "second malformed doc must fail the whole load"
    );
}

#[test]
fn from_reader_list_values() {
    let docs = load("apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nspec:\n  containers:\n  - name: c1\n    image: img1\n  - name: c2\n    image: img2\n").unwrap();
    let spec = docs[0].get("spec").and_then(Value::as_mapping).unwrap();
    let containers = spec
        .get("containers")
        .and_then(Value::as_sequence)
        .expect("containers is a list");
    assert_eq!(containers.len(), 2);
}

#[test]
fn from_reader_null_values() {
    let docs = load("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  key1: ~\n  key2: null\n  key3: value\n").unwrap();
    let data = docs[0].get("data").and_then(Value::as_mapping).unwrap();
    assert_eq!(data.get("key1"), Some(&Value::Null));
    assert_eq!(data.get("key2"), Some(&Value::Null));
    assert_eq!(data.get("key3").and_then(Value::as_str), Some("value"));
}

#[test]
fn from_reader_numeric_values() {
    let docs = load("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  replicas: 3\n  ratio: 1.5\n").unwrap();
    let data = docs[0].get("data").and_then(Value::as_mapping).unwrap();
    assert_eq!(data.get("replicas").and_then(Value::as_i64), Some(3));
    assert_eq!(data.get("ratio").and_then(Value::as_f64), Some(1.5));
}

#[test]
fn from_reader_multiline_string() {
    let docs = load("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  script: |\n    #!/bin/bash\n    echo \"hello\"\n    exit 0\n").unwrap();
    let data = docs[0].get("data").and_then(Value::as_mapping).unwrap();
    let script = data
        .get("script")
        .and_then(Value::as_str)
        .expect("script is a string");
    assert!(script.contains("echo"));
}

#[test]
fn from_reader_large_document() {
    let mut s = String::from("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: large\ndata:\n");
    for i in 0..100u8 {
        let a = (b'a' + i % 26) as char;
        let b = (b'a' + i / 26) as char;
        s.push_str(&format!("  keyxxxxx{a}{b}: value\n"));
    }
    let docs = load(&s).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(
        docs[0]
            .get("data")
            .and_then(Value::as_mapping)
            .unwrap()
            .len(),
        100
    );
}

// ---------- yaml.v3 parity rules (Rust-specific) ----------

#[test]
fn parity_scalar_keys_become_strings() {
    let docs = load("1: one\ntrue: yes\nnested:\n  2: two\n").unwrap();
    assert_eq!(docs[0].get("1").and_then(Value::as_str), Some("one"));
    assert_eq!(docs[0].get("true").and_then(Value::as_str), Some("yes"));
    let nested = docs[0].get("nested").and_then(Value::as_mapping).unwrap();
    assert_eq!(nested.get("2").and_then(Value::as_str), Some("two"));
}

#[test]
fn parity_yaml11_booleans_stay_strings() {
    let docs = load("a: yes\nb: on\nc: true\n").unwrap();
    assert_eq!(docs[0].get("a").and_then(Value::as_str), Some("yes"));
    assert_eq!(docs[0].get("b").and_then(Value::as_str), Some("on"));
    assert_eq!(docs[0].get("c"), Some(&Value::Bool(true)));
}

#[test]
fn parity_merge_keys_expanded() {
    let docs = load("base: &b {k: v}\nderived:\n  <<: *b\n  z: 1\n").unwrap();
    let derived = docs[0].get("derived").and_then(Value::as_mapping).unwrap();
    assert_eq!(derived.get("k").and_then(Value::as_str), Some("v"));
    assert_eq!(derived.get("z").and_then(Value::as_i64), Some(1));
    assert!(derived.get("<<").is_none());
}

#[test]
fn parity_duplicate_key_is_error() {
    assert!(matches!(load("a: 1\na: 2\n"), Err(ParseError::Yaml(_))));
}

#[test]
fn parity_non_mapping_root_is_error() {
    assert!(matches!(load("- a\n- b\n"), Err(ParseError::NotAMapping)));
    assert!(matches!(
        load("just a scalar\n"),
        Err(ParseError::NotAMapping)
    ));
}

#[test]
fn parity_tagged_scalar_loses_tag() {
    let docs = load("kind: !!str Pod\nn: !custom 5\n").unwrap();
    assert_eq!(kind(&docs[0]), "Pod");
    assert_eq!(docs[0].get("n").and_then(Value::as_i64), Some(5));
}

#[test]
fn parse_error_display_prefix() {
    let err = load("a: [\n").unwrap_err();
    assert!(err.to_string().starts_with("yaml: "), "{err}");
    assert_eq!(
        ParseError::NotAMapping.to_string(),
        "yaml: cannot unmarshal non-mapping document"
    );
}
