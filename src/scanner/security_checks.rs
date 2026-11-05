//! Individual security checks run against one parsed YAML document.
//!
//! Every rule takes untyped YAML (`Mapping` / `Value`) and returns `1` for a
//! violation or `0` otherwise, exactly like the Go implementation. Missing or
//! wrongly typed fields never panic: the helpers below turn them into "absent".

use serde_yaml_ng::{Mapping, Value};

#[cfg(test)]
#[path = "security_checks_tests.rs"]
mod tests;

// ---------- helpers ----------

/// Returns the mapping behind `v`, or `None` if `v` is absent or not a mapping.
pub(super) fn as_map(v: Option<&Value>) -> Option<&Mapping> {
    v.and_then(Value::as_mapping)
}

/// Returns the sequence behind `v`, or an empty slice if absent or not a sequence.
pub(super) fn as_slice(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_sequence)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Returns the string behind `v`, or `""` if absent or not a string.
pub(super) fn str_of(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("")
}

/// Returns the bool behind `v`, or `false` if absent or not a bool
/// (the string `"true"` is *not* a bool).
pub(super) fn bool_of(v: Option<&Value>) -> bool {
    v.and_then(Value::as_bool).unwrap_or(false)
}

/// Case-insensitive ASCII comparison, used for `kind` values.
fn eq_fold(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Returns true if the document has non-empty `apiVersion` and `kind`
/// fields, i.e. it is a valid Kubernetes resource.
pub(super) fn has_api_version_and_kind(doc: &Mapping) -> bool {
    !str_of(doc.get("apiVersion")).is_empty() && !str_of(doc.get("kind")).is_empty()
}

/// Returns true if `metadata.labels` marks the document as Helm-managed:
/// `app.kubernetes.io/managed-by: Helm` or any `helm.sh/chart` label.
pub(super) fn detect_helm_managed(doc: &Mapping) -> bool {
    let Some(meta) = as_map(doc.get("metadata")) else {
        return false;
    };
    let Some(labels) = as_map(meta.get("labels")) else {
        return false;
    };
    if str_of(labels.get("app.kubernetes.io/managed-by")) == "Helm" {
        return true;
    }
    labels.get("helm.sh/chart").is_some_and(|v| !v.is_null())
}

// ---------- rules ----------

/// Returns 1 if the document is a `Secret` with at least one entry in
/// `data` or `stringData`, otherwise 0.
pub(super) fn count_secrets_in_doc(doc: &Mapping) -> u8 {
    if eq_fold(str_of(doc.get("kind")), "Secret") {
        let data = as_map(doc.get("data")).map_or(0, Mapping::len);
        let string_data = as_map(doc.get("stringData")).map_or(0, Mapping::len);
        if data > 0 || string_data > 0 {
            return 1;
        }
    }
    0
}

/// Returns 1 if any key or string value anywhere in the document contains
/// `http://` (case-insensitive), i.e. a plaintext HTTP URL. Otherwise 0.
pub(super) fn has_insecure_http(doc: &Mapping) -> u8 {
    fn walk(v: &Value) -> bool {
        match v {
            Value::String(s) => s.to_lowercase().contains("http://"),
            Value::Sequence(xs) => xs.iter().any(walk),
            Value::Mapping(m) => m.iter().any(|(k, v)| {
                k.as_str()
                    .is_some_and(|k| k.to_lowercase().contains("http://"))
                    || walk(v)
            }),
            _ => false,
        }
    }
    u8::from(doc.iter().any(|(k, v)| {
        k.as_str()
            .is_some_and(|k| k.to_lowercase().contains("http://"))
            || walk(v)
    }))
}

/// Collects all container definitions (regular and init) from a pod spec.
/// Also descends into `template.spec` for callers that pass a workload spec.
pub(super) fn containers_from_spec(spec: &Mapping) -> Vec<&Value> {
    let mut all: Vec<&Value> = Vec::new();
    all.extend(as_slice(spec.get("containers")));
    all.extend(as_slice(spec.get("initContainers")));
    if let Some(s2) = as_map(spec.get("template")).and_then(|t| as_map(t.get("spec"))) {
        all.extend(as_slice(s2.get("containers")));
        all.extend(as_slice(s2.get("initContainers")));
    }
    all
}

/// Extracts the pod-level spec from a document.
///
/// - `Pod`: `spec`
/// - `CronJob`: `spec.jobTemplate.spec.template.spec`
/// - other workloads (Deployment, StatefulSet, ...): `spec.template.spec`
///
/// Returns `None` for non-workload documents.
pub(super) fn pod_spec_from_doc(doc: &Mapping) -> Option<&Mapping> {
    let mut sp = as_map(doc.get("spec"));
    if eq_fold(str_of(doc.get("kind")), "Pod") {
        return sp;
    }
    // CronJob wraps the pod template one level deeper.
    if let Some(jt) = sp.and_then(|s| as_map(s.get("jobTemplate"))) {
        sp = as_map(jt.get("spec"));
    }
    sp.and_then(|s| as_map(s.get("template")))
        .and_then(|t| as_map(t.get("spec")))
}

/// Returns 1 if the pod spec has no pod-level `securityContext` AND none of
/// its containers define one. Returns 0 for non-workload documents or when
/// at least one security context is present.
pub(super) fn lack_security_context(spec: Option<&Mapping>) -> u8 {
    let Some(spec) = spec else {
        return 0;
    };
    if as_map(spec.get("securityContext")).is_some() {
        return 0;
    }
    let containers = containers_from_spec(spec);
    if containers.is_empty() {
        return 0;
    }
    let any_has_sc = containers.iter().any(|c| {
        as_map(Some(c))
            .and_then(|c| c.get("securityContext"))
            .is_some_and(|v| !v.is_null())
    });
    u8::from(!any_has_sc)
}

/// Returns 1 if any container lacks both resource `limits` and `requests`.
/// Returns 0 for non-workload documents or when every container has at
/// least one of them.
pub(super) fn lack_resources(spec: Option<&Mapping>) -> u8 {
    let Some(spec) = spec else {
        return 0;
    };
    let containers = containers_from_spec(spec);
    if containers.is_empty() {
        return 0;
    }
    for c in containers {
        let res = as_map(Some(c)).and_then(|c| as_map(c.get("resources")));
        let limits = res
            .and_then(|r| as_map(r.get("limits")))
            .map_or(0, Mapping::len);
        let requests = res
            .and_then(|r| as_map(r.get("requests")))
            .map_or(0, Mapping::len);
        if limits == 0 && requests == 0 {
            return 1;
        }
    }
    0
}

/// Returns `(hostPID, hostIPC, hostNetwork)` as 1 for each flag set to `true`.
/// All 0 if `spec` is `None`.
pub(super) fn check_host_flags(spec: Option<&Mapping>) -> (u8, u8, u8) {
    let Some(spec) = spec else {
        return (0, 0, 0);
    };
    (
        u8::from(bool_of(spec.get("hostPID"))),
        u8::from(bool_of(spec.get("hostIPC"))),
        u8::from(bool_of(spec.get("hostNetwork"))),
    )
}

/// Returns 1 if any volume mounts the Docker socket (`/var/run/docker.sock`)
/// through `hostPath`, otherwise 0.
pub(super) fn check_docker_sock(spec: Option<&Mapping>) -> u8 {
    let Some(spec) = spec else {
        return 0;
    };
    for v in as_slice(spec.get("volumes")) {
        let hp = as_map(Some(v)).and_then(|v| as_map(v.get("hostPath")));
        if str_of(hp.and_then(|h| h.get("path"))).contains("/var/run/docker.sock") {
            return 1;
        }
    }
    0
}

/// Inspects every container's `securityContext` and returns
/// `(capSysAdmin, capSysModule, allowPrivi, seccompUnconfined)`: 1 when the
/// `SYS_ADMIN` / `SYS_MODULE` capability is added, `allowPrivilegeEscalation`
/// is true, or `seccompProfile.type` is `Unconfined`. All 0 if `spec` is `None`.
pub(super) fn check_caps(spec: Option<&Mapping>) -> (u8, u8, u8, u8) {
    let (mut cap_sys_admin, mut cap_sys_module, mut allow_privi, mut seccomp_unconfined) =
        (0, 0, 0, 0);
    let Some(spec) = spec else {
        return (0, 0, 0, 0);
    };
    for c in containers_from_spec(spec) {
        let Some(sc) = as_map(Some(c)).and_then(|c| as_map(c.get("securityContext"))) else {
            continue;
        };
        let adds = as_map(sc.get("capabilities")).map_or(&[][..], |caps| as_slice(caps.get("add")));
        for a in adds {
            let val = str_of(Some(a)).to_uppercase();
            if val == "SYS_ADMIN" {
                cap_sys_admin = 1;
            }
            if val == "SYS_MODULE" {
                cap_sys_module = 1;
            }
        }
        if bool_of(sc.get("allowPrivilegeEscalation")) {
            allow_privi = 1;
        }
        if let Some(sp) = as_map(sc.get("seccompProfile")) {
            if eq_fold(str_of(sp.get("type")), "Unconfined") {
                seccomp_unconfined = 1;
            }
        }
    }
    (
        cap_sys_admin,
        cap_sys_module,
        allow_privi,
        seccomp_unconfined,
    )
}

/// Returns 1 if any container sets `securityContext.privileged: true`,
/// which grants full access to the host kernel. Otherwise 0.
pub(super) fn check_privileged(spec: Option<&Mapping>) -> u8 {
    let Some(spec) = spec else {
        return 0;
    };
    for c in containers_from_spec(spec) {
        let sc = as_map(Some(c)).and_then(|c| as_map(c.get("securityContext")));
        if bool_of(sc.and_then(|sc| sc.get("privileged"))) {
            return 1;
        }
    }
    0
}

/// Returns 1 if the pod spec defines any `hostAliases` entries (custom
/// `/etc/hosts` mappings), otherwise 0.
pub(super) fn has_host_aliases(spec: Option<&Mapping>) -> u8 {
    spec.map_or(0, |s| u8::from(!as_slice(s.get("hostAliases")).is_empty()))
}

/// Returns 1 if the document is a `Deployment` that uses the `Recreate`
/// strategy or has no `rollingUpdate` configuration. 0 for other kinds.
pub(super) fn lack_rolling_update(doc: &Mapping) -> u8 {
    if !eq_fold(str_of(doc.get("kind")), "Deployment") {
        return 0;
    }
    let strat = as_map(doc.get("spec")).and_then(|s| as_map(s.get("strategy")));
    if str_of(strat.and_then(|s| s.get("type"))).to_lowercase() == "recreate" {
        return 1;
    }
    if strat.and_then(|s| as_map(s.get("rollingUpdate"))).is_none() {
        return 1;
    }
    0
}

/// Returns 1 if `metadata.namespace` is missing or empty, which may mean the
/// resource lands in the default namespace. Cluster-scoped kinds are flagged too.
pub(super) fn lack_namespace(doc: &Mapping) -> u8 {
    let ns = str_of(as_map(doc.get("metadata")).and_then(|m| m.get("namespace")));
    u8::from(ns.is_empty())
}
