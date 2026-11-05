//! Output row data structure.

use serde::Serialize;

/// Result of all security checks for one YAML document.
///
/// Each `u8` field is binary (0 or 1), where 1 means a violation was detected.
/// Fields map 1:1 to the CSV columns in `config::CSV_HEADER`; the JSON keys are
/// the snake_case field names, identical to the Go implementation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Row {
    /// Parent directory (chart) path, or the input label in stdin mode.
    pub dir: String,
    /// Full path to the analyzed YAML file, or the input label in stdin mode.
    pub yaml_full_path: String,
    /// 1 if the document is a Secret with data/stringData entries.
    pub within_manifest_secret: u8,
    /// 1 if a Secret is detected via taint analysis (reserved, always 0).
    pub valid_taint_secret: u8,
    /// 1 if any container runs in privileged mode.
    pub sec_cont_over_privil: u8,
    /// 1 if any key or value contains an "http://" URL.
    pub insecure_http: u8,
    /// 1 if no securityContext is defined at pod or container level.
    pub no_secu_context: u8,
    /// 1 if the resource has no namespace in metadata.
    pub no_default_nspace: u8,
    /// 1 if any container lacks both resource limits and requests.
    pub no_reso: u8,
    /// 1 if a Deployment lacks a rolling update strategy.
    pub no_rolling_update: u8,
    /// 1 if no NetworkPolicy exists in the chart.
    pub no_network_policy: u8,
    /// 1 if hostPID is true.
    pub true_host_pid: u8,
    /// 1 if hostIPC is true.
    pub true_host_ipc: u8,
    /// 1 if /var/run/docker.sock is mounted via hostPath.
    pub dockersock_path: u8,
    /// 1 if hostNetwork is true.
    pub true_host_net: u8,
    /// 1 if the SYS_ADMIN capability is added.
    pub cap_sys_admin: u8,
    /// 1 if hostAliases are defined in the pod spec.
    pub host_alias: u8,
    /// 1 if allowPrivilegeEscalation is true.
    pub allow_privi: u8,
    /// 1 if the seccomp profile type is Unconfined.
    pub seccomp_unconfined: u8,
    /// 1 if the SYS_MODULE capability is added.
    pub cap_sys_module: u8,
    /// true if the document has both apiVersion and kind.
    pub k8s_status: bool,
    /// true if the document is managed by Helm.
    pub helm_status: bool,
}

impl Row {
    /// Returns the CSV record for this row, in `config::CSV_HEADER` order.
    ///
    /// Binary check fields are rendered as "0"/"1"; status fields as
    /// "true"/"false", matching the Go implementation.
    pub fn to_csv_record(&self) -> [String; 22] {
        [
            self.dir.clone(),
            self.yaml_full_path.clone(),
            self.within_manifest_secret.to_string(),
            self.valid_taint_secret.to_string(),
            self.sec_cont_over_privil.to_string(),
            self.insecure_http.to_string(),
            self.no_secu_context.to_string(),
            self.no_default_nspace.to_string(),
            self.no_reso.to_string(),
            self.no_rolling_update.to_string(),
            self.no_network_policy.to_string(),
            self.true_host_pid.to_string(),
            self.true_host_ipc.to_string(),
            self.dockersock_path.to_string(),
            self.true_host_net.to_string(),
            self.cap_sys_admin.to_string(),
            self.host_alias.to_string(),
            self.allow_privi.to_string(),
            self.seccomp_unconfined.to_string(),
            self.cap_sys_module.to_string(),
            self.k8s_status.to_string(),
            self.helm_status.to_string(),
        ]
    }
}
