//! Manifest scanning: file walking and per-document analysis orchestration.

pub mod row;
pub mod security_checks;

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod tests;

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::parser::{self, Doc, ParseError};
use security_checks::*;

pub use row::Row;

/// Returns true if the path has a `.yaml` or `.yml` extension (case-insensitive).
pub fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
}

/// Lists every YAML file under `root`, recursively, in lexical order
/// (the same order Go's `filepath.WalkDir` uses). Unreadable entries are skipped.
pub fn yaml_files(root: impl AsRef<Path>) -> Vec<PathBuf> {
    walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && is_yaml(e.path()))
        .map(walkdir::DirEntry::into_path)
        .collect()
}

/// Lexically cleans a path like Go's `filepath.Clean`: drops `.` segments,
/// resolves `..` against preceding segments, collapses separators and
/// removes a trailing slash. An empty result becomes `.`.
fn clean_path(path: &Path) -> String {
    let mut parts: Vec<Component<'_>> = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match parts.last() {
                Some(Component::Normal(_)) => {
                    parts.pop();
                }
                Some(Component::RootDir) => {}
                _ => parts.push(c),
            },
            other => parts.push(other),
        }
    }
    let cleaned: PathBuf = parts.iter().collect();
    let s = cleaned.to_string_lossy().into_owned();
    if s.is_empty() { ".".to_string() } else { s }
}

/// Returns true if `doc` is a `NetworkPolicy` (case-insensitive kind).
fn is_network_policy(doc: &Doc) -> bool {
    str_of(doc.get("kind")).eq_ignore_ascii_case("NetworkPolicy")
}

/// Walks all YAML files under `root_dir` and returns true if any document
/// has kind `NetworkPolicy`. This chart-level pre-scan feeds the
/// `no_network_policy` flag of every row produced from that chart. Stops at
/// the first match; malformed files are skipped.
pub fn has_network_policy(root_dir: impl AsRef<Path>) -> bool {
    yaml_files(root_dir).iter().any(|p| {
        parser::load_yaml_docs(p)
            .map(|docs| docs.iter().any(is_network_policy))
            .unwrap_or(false)
    })
}

/// Runs every security check on one document and builds its `Row`.
fn analyze_doc(doc: &Doc, dir: &str, yaml_full_path: &str, has_np: bool) -> Row {
    let ps = pod_spec_from_doc(doc);
    let (true_host_pid, true_host_ipc, true_host_net) = check_host_flags(ps);
    let (cap_sys_admin, cap_sys_module, allow_privi, seccomp_unconfined) = check_caps(ps);
    Row {
        dir: dir.to_string(),
        yaml_full_path: yaml_full_path.to_string(),
        k8s_status: has_api_version_and_kind(doc),
        helm_status: detect_helm_managed(doc),
        within_manifest_secret: count_secrets_in_doc(doc),
        valid_taint_secret: 0, // reserved
        insecure_http: has_insecure_http(doc),
        no_secu_context: lack_security_context(ps),
        no_reso: lack_resources(ps),
        true_host_pid,
        true_host_ipc,
        true_host_net,
        dockersock_path: check_docker_sock(ps),
        sec_cont_over_privil: check_privileged(ps),
        cap_sys_admin,
        cap_sys_module,
        allow_privi,
        seccomp_unconfined,
        host_alias: has_host_aliases(ps),
        no_rolling_update: lack_rolling_update(doc),
        no_default_nspace: lack_namespace(doc),
        no_network_policy: u8::from(!has_np),
    }
}

/// Parses a multi-document YAML file and returns one `Row` per document.
///
/// `has_np` is the chart-level result of [`has_network_policy`]; `root_dir`
/// is recorded verbatim in `Row::dir`, the file path is cleaned into
/// `Row::yaml_full_path`. Fails only if the file cannot be read or parsed.
pub fn analyze_file(
    path: impl AsRef<Path>,
    root_dir: &str,
    has_np: bool,
) -> Result<Vec<Row>, ParseError> {
    let path = path.as_ref();
    let docs = parser::load_yaml_docs(path)?;
    let full_path = clean_path(path);
    Ok(docs
        .iter()
        .map(|d| analyze_doc(d, root_dir, &full_path, has_np))
        .collect())
}

/// Reads multi-document YAML from a reader (e.g. stdin) and returns one
/// `Row` per document. The NetworkPolicy pre-scan runs over the same stream.
/// `label` is used for both `Row::dir` and `Row::yaml_full_path`.
pub fn analyze_reader<R: Read>(r: R, label: &str) -> Result<Vec<Row>, ParseError> {
    let docs = parser::load_yaml_docs_from_reader(r)?;
    let has_np = docs.iter().any(is_network_policy);
    Ok(docs
        .iter()
        .map(|d| analyze_doc(d, label, label, has_np))
        .collect())
}
