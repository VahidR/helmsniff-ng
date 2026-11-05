//! Tests for the scanning orchestration (`is_yaml`, `yaml_files`,
//! `clean_path`, `has_network_policy`, `analyze_file`, `analyze_reader`).
//! Mirrors the Go `scanner_test.go` suite.

use super::*;
use std::fs;

use tempfile::{TempDir, tempdir};

/// Writes `content` to `<dir>/<name>` (creating parent dirs) and returns the path.
fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).expect("write test file");
    path
}

/// Writes `content` into a fresh temp dir and analyzes it with `analyze_file`.
/// Returns the temp dir (kept alive), the file path and the rows.
fn analyze_str(content: &str, has_np: bool) -> (TempDir, PathBuf, Vec<Row>) {
    let dir = tempdir().unwrap();
    let path = write_file(dir.path(), "doc.yaml", content);
    let rows = analyze_file(&path, dir.path().to_str().unwrap(), has_np).expect("analyze_file");
    (dir, path, rows)
}

/// Analyzes `content` through the reader entry point.
fn analyze_text(content: &str, label: &str) -> Vec<Row> {
    analyze_reader(content.as_bytes(), label).expect("analyze_reader")
}

const CLEAN_DEPLOYMENT: &str = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
";

// ---------- is_yaml ----------

#[test]
fn is_yaml_cases() {
    let table: &[(&str, bool)] = &[
        ("deployment.yaml", true),
        ("service.yml", true),
        ("chart.YAML", true),
        ("values.YML", true),
        ("readme.md", false),
        ("config.json", false),
        ("noext", false),
        ("path/to/file.yaml", true),
        ("path/to/file.txt", false),
        (".yaml", false), // dotfile without extension (Go: true via filepath.Ext)
        ("", false),
    ];
    for (path, want) in table {
        assert_eq!(is_yaml(Path::new(path)), *want, "path: {path:?}");
    }
}

// ---------- yaml_files / clean_path ----------

#[test]
fn yaml_files_recursive_sorted_and_filtered() {
    let dir = tempdir().unwrap();
    write_file(dir.path(), "b.yaml", "");
    write_file(dir.path(), "a.yml", "");
    write_file(dir.path(), "notes.txt", "");
    write_file(dir.path(), "templates/z.yaml", "");
    write_file(dir.path(), "templates/sub/y.YAML", "");
    let got: Vec<String> = yaml_files(dir.path())
        .iter()
        .map(|p| {
            p.strip_prefix(dir.path())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        got,
        [
            "a.yml",
            "b.yaml",
            "templates/sub/y.YAML",
            "templates/z.yaml"
        ]
    );
}

#[test]
fn yaml_files_missing_root_is_empty() {
    assert!(yaml_files("/nonexistent/dir").is_empty());
}

#[test]
fn clean_path_matches_go_filepath_clean() {
    let table: &[(&str, &str)] = &[
        ("a/b/c.yaml", "a/b/c.yaml"),
        ("./a.yaml", "a.yaml"),
        ("a//b.yaml", "a/b.yaml"),
        ("a/./b.yaml", "a/b.yaml"),
        ("a/../b.yaml", "b.yaml"),
        ("../b.yaml", "../b.yaml"),
        ("/../b.yaml", "/b.yaml"),
        ("/a/b/", "/a/b"),
        ("", "."),
        (".", "."),
        ("a/b/../../..", ".."),
    ];
    for (input, want) in table {
        assert_eq!(clean_path(Path::new(input)), *want, "input: {input:?}");
    }
}

// ---------- has_network_policy ----------

#[test]
fn has_network_policy_found() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "netpol.yaml",
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny-all\nspec:\n  podSelector: {}\n",
    );
    assert!(has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_not_found() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
    );
    assert!(!has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_case_insensitive() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "np.yaml",
        "apiVersion: networking.k8s.io/v1\nkind: networkpolicy\nmetadata:\n  name: test\n",
    );
    assert!(has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_empty_dir() {
    let dir = tempdir().unwrap();
    assert!(!has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_non_yaml_files_ignored() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "netpol.json",
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test\n",
    );
    assert!(!has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_multi_doc() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "multi.yaml",
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n",
    );
    assert!(has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_nested_dir() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "templates/netpol.yaml",
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: np\n",
    );
    assert!(has_network_policy(dir.path()));
}

#[test]
fn has_network_policy_malformed_yaml_skipped() {
    let dir = tempdir().unwrap();
    write_file(dir.path(), "bad.yaml", "{{{{ not valid yaml");
    write_file(dir.path(), "np.yaml", "kind: NetworkPolicy\n");
    assert!(
        has_network_policy(dir.path()),
        "malformed file must be skipped, not abort the scan"
    );
    fs::remove_file(dir.path().join("np.yaml")).unwrap();
    assert!(!has_network_policy(dir.path()));
}

// ---------- analyze_file ----------

#[test]
fn analyze_file_deployment() {
    let content = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.sh/chart: mychart-1.0.0
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
        securityContext:
          runAsNonRoot: true
";
    let (dir, path, rows) = analyze_str(content, true);
    assert_eq!(
        rows,
        [Row {
            dir: dir.path().to_string_lossy().into_owned(),
            yaml_full_path: path.to_string_lossy().into_owned(),
            k8s_status: true,
            helm_status: true,
            ..Default::default()
        }],
        "a fully compliant Deployment must produce an all-zero row"
    );
}

#[test]
fn analyze_file_violations() {
    let content = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  template:
    spec:
      hostPID: true
      hostIPC: true
      hostNetwork: true
      hostAliases:
      - ip: \"1.2.3.4\"
        hostnames:
        - \"evil.com\"
      containers:
      - name: app
        image: nginx
        env:
        - name: ENDPOINT
          value: \"http://insecure-api.example.com\"
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_MODULE
          seccompProfile:
            type: Unconfined
      volumes:
      - name: docker
        hostPath:
          path: /var/run/docker.sock
";
    let (dir, path, rows) = analyze_str(content, false);
    assert_eq!(
        rows,
        [Row {
            dir: dir.path().to_string_lossy().into_owned(),
            yaml_full_path: path.to_string_lossy().into_owned(),
            k8s_status: true,
            helm_status: false,
            within_manifest_secret: 0,
            valid_taint_secret: 0,
            sec_cont_over_privil: 1,
            insecure_http: 1,
            no_secu_context: 0,
            no_default_nspace: 1,
            no_reso: 1,
            no_rolling_update: 1,
            no_network_policy: 1,
            true_host_pid: 1,
            true_host_ipc: 1,
            dockersock_path: 1,
            true_host_net: 1,
            cap_sys_admin: 1,
            host_alias: 1,
            allow_privi: 1,
            seccomp_unconfined: 1,
            cap_sys_module: 1,
        }]
    );
}

#[test]
fn analyze_file_secret_data() {
    let (_d, _p, rows) = analyze_str(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\n  namespace: default\ndata:\n  password: cGFzc3dvcmQ=\n",
        false,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].within_manifest_secret, 1);
}

#[test]
fn analyze_file_secret_string_data() {
    let (_d, _p, rows) = analyze_str(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: my-secret\n  namespace: default\nstringData:\n  token: abc123\n",
        false,
    );
    assert_eq!(rows[0].within_manifest_secret, 1);
}

#[test]
fn analyze_file_secret_empty_data() {
    let (_d, _p, rows) = analyze_str(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: empty-secret\n  namespace: default\ndata: {}\n",
        false,
    );
    assert_eq!(rows[0].within_manifest_secret, 0);
}

#[test]
fn analyze_file_multi_document() {
    let content = "apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
";
    let (_d, _p, rows) = analyze_str(content, false);
    assert_eq!(rows.len(), 2);
    // Service: non-workload, pod-level checks are 0
    assert_eq!(rows[0].no_secu_context, 0);
    assert_eq!(rows[0].no_reso, 0);
    assert_eq!(rows[0].true_host_pid, 0);
    assert!(rows[1].k8s_status);
}

#[test]
fn analyze_file_pod() {
    let content = "apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: app
    image: busybox
    resources:
      requests:
        memory: 64Mi
    securityContext:
      runAsNonRoot: true
";
    let (_d, _p, rows) = analyze_str(content, true);
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert!(r.k8s_status);
    assert_eq!(
        (r.no_secu_context, r.no_reso, r.no_network_policy),
        (0, 0, 0)
    );
}

#[test]
fn analyze_file_non_workload_kind() {
    let (_d, _p, rows) = analyze_str(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-config\n  namespace: default\ndata:\n  key: value\n",
        false,
    );
    let r = &rows[0];
    assert_eq!(
        (
            r.no_secu_context,
            r.no_reso,
            r.true_host_pid,
            r.true_host_ipc,
            r.true_host_net,
            r.dockersock_path,
            r.cap_sys_admin,
            r.host_alias
        ),
        (0, 0, 0, 0, 0, 0, 0, 0),
        "non-workload: every pod-level check is 0"
    );
}

#[test]
fn analyze_file_invalid_path() {
    assert!(matches!(
        analyze_file("/nonexistent/path.yaml", "/nonexistent", false),
        Err(ParseError::Io(_))
    ));
}

#[test]
fn analyze_file_malformed_yaml() {
    let dir = tempdir().unwrap();
    let path = write_file(dir.path(), "bad.yaml", "{{{{ invalid yaml content");
    assert!(matches!(
        analyze_file(&path, dir.path().to_str().unwrap(), false),
        Err(ParseError::Yaml(_))
    ));
}

#[test]
fn analyze_file_empty_file() {
    let (_d, _p, rows) = analyze_str("", false);
    assert!(rows.is_empty());
}

#[test]
fn analyze_file_only_separators() {
    let (_d, _p, rows) = analyze_str("---\n---\n---\n", false);
    assert!(rows.is_empty());
}

#[test]
fn analyze_file_recreate_strategy() {
    let content = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
";
    let (_d, _p, rows) = analyze_str(content, false);
    assert_eq!(rows[0].no_rolling_update, 1);
}

#[test]
fn analyze_file_stateful_set() {
    let content = "apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: data
spec:
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:14
        resources:
          limits:
            memory: 1Gi
        securityContext:
          runAsUser: 999
";
    let (_d, _p, rows) = analyze_str(content, false);
    let r = &rows[0];
    assert!(r.k8s_status);
    assert_eq!(
        (r.no_secu_context, r.no_reso, r.no_rolling_update),
        (0, 0, 0)
    );
}

#[test]
fn analyze_file_daemon_set() {
    let content = "apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: logger
  namespace: monitoring
spec:
  template:
    spec:
      containers:
      - name: fluentd
        image: fluentd:latest
";
    let (_d, _p, rows) = analyze_str(content, false);
    assert_eq!((rows[0].no_secu_context, rows[0].no_reso), (1, 1));
}

#[test]
fn analyze_file_cron_job_clean() {
    let content = "apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
  namespace: ops
spec:
  schedule: \"0 2 * * *\"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: backup:latest
            resources:
              limits:
                cpu: 500m
            securityContext:
              runAsNonRoot: true
";
    let (_d, _p, rows) = analyze_str(content, false);
    let r = &rows[0];
    assert!(r.k8s_status);
    // Pod-level checks must reach spec.jobTemplate.spec.template.spec.
    assert_eq!(
        (r.no_reso, r.no_secu_context, r.sec_cont_over_privil),
        (0, 0, 0)
    );
}

#[test]
fn analyze_file_cron_job_violations() {
    let content = "apiVersion: batch/v1
kind: CronJob
metadata:
  name: risky-cron
  namespace: ops
spec:
  schedule: \"*/5 * * * *\"
  jobTemplate:
    spec:
      template:
        spec:
          hostPID: true
          hostNetwork: true
          containers:
          - name: job
            image: job:latest
            securityContext:
              privileged: true
              capabilities:
                add:
                - SYS_ADMIN
          volumes:
          - name: docker
            hostPath:
              path: /var/run/docker.sock
";
    let (_d, _p, rows) = analyze_str(content, false);
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (
            r.true_host_pid,
            r.true_host_net,
            r.sec_cont_over_privil,
            r.cap_sys_admin,
            r.dockersock_path,
            r.no_reso,
            r.no_secu_context
        ),
        (1, 1, 1, 1, 1, 1, 0)
    );
}

#[test]
fn analyze_file_init_containers() {
    let content = "apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      initContainers:
      - name: init
        image: busybox
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
";
    let (_d, _p, rows) = analyze_str(content, false);
    assert_eq!(rows[0].no_reso, 1, "initContainer lacks resources");
}

#[test]
fn analyze_file_path_cleaning() {
    let dir = tempdir().unwrap();
    write_file(
        dir.path(),
        "test.yaml",
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
    );
    let messy = dir.path().join(".").join("test.yaml");
    let rows = analyze_file(&messy, dir.path().to_str().unwrap(), false).unwrap();
    assert!(
        !rows[0].yaml_full_path.contains("/./"),
        "not cleaned: {}",
        rows[0].yaml_full_path
    );
    assert_eq!(
        rows[0].yaml_full_path,
        dir.path().join("test.yaml").to_string_lossy()
    );
}

#[test]
fn analyze_file_row_metadata() {
    let dir = tempdir().unwrap();
    let path = write_file(
        dir.path(),
        "test.yaml",
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
    );
    let rows = analyze_file(&path, "/charts/mychart", false).unwrap();
    assert_eq!(
        rows[0].dir, "/charts/mychart",
        "root_dir is recorded verbatim"
    );
    assert_eq!(rows[0].yaml_full_path, clean_path(&path));
}

#[test]
fn analyze_file_no_helm_labels() {
    let (_d, _p, rows) = analyze_str(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  labels:\n    app: myapp\n",
        false,
    );
    assert!(!rows[0].helm_status);
}

#[test]
fn analyze_file_has_np_flag() {
    let (_d, _p, with_np) = analyze_str(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
        true,
    );
    let (_d2, _p2, without_np) = analyze_str(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
        false,
    );
    assert_eq!(with_np[0].no_network_policy, 0);
    assert_eq!(without_np[0].no_network_policy, 1);
}

// ---------- analyze_reader ----------

#[test]
fn analyze_reader_single_doc() {
    let rows = analyze_text(CLEAN_DEPLOYMENT, "stdin");
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (r.dir.as_str(), r.yaml_full_path.as_str()),
        ("stdin", "stdin")
    );
    assert!(r.k8s_status);
    assert_eq!(r.no_network_policy, 1);
}

#[test]
fn analyze_reader_with_network_policy() {
    let input = format!(
        "{CLEAN_DEPLOYMENT}---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {{}}
"
    );
    let rows = analyze_text(&input, "pipe");
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().all(|r| r.no_network_policy == 0),
        "NP in the stream clears the flag on every row"
    );
}

#[test]
fn analyze_reader_empty() {
    assert!(analyze_text("", "empty").is_empty());
}

#[test]
fn analyze_reader_malformed_yaml() {
    assert!(matches!(
        analyze_reader("{{{{ bad yaml".as_bytes(), "bad"),
        Err(ParseError::Yaml(_))
    ));
}

#[test]
fn analyze_reader_multiple_violations() {
    let input = "apiVersion: v1
kind: Pod
metadata:
  name: danger-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: evil
    image: evil:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      capabilities:
        add:
        - SYS_ADMIN
  volumes:
  - name: docker
    hostPath:
      path: /var/run/docker.sock
";
    let rows = analyze_text(input, "test");
    let r = &rows[0];
    assert_eq!(
        (
            r.true_host_pid,
            r.true_host_net,
            r.allow_privi,
            r.cap_sys_admin,
            r.dockersock_path,
            r.sec_cont_over_privil,
            r.no_reso,
            r.no_default_nspace
        ),
        (1, 1, 1, 1, 1, 1, 1, 1)
    );
}

#[test]
fn analyze_reader_pod_security_context() {
    let input = "apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: prod
spec:
  securityContext:
    runAsNonRoot: true
    fsGroup: 1000
  containers:
  - name: app
    image: app:latest
    resources:
      limits:
        cpu: 100m
";
    assert_eq!(
        analyze_text(input, "test")[0].no_secu_context,
        0,
        "pod-level securityContext suffices"
    );
}

#[test]
fn analyze_reader_helm_chart_label() {
    let rows = analyze_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  namespace: default\n  labels:\n    helm.sh/chart: myapp-0.1.0\n",
        "test",
    );
    assert!(rows[0].helm_status);
}

#[test]
fn analyze_reader_no_api_version() {
    let rows = analyze_text(
        "kind: ConfigMap\nmetadata:\n  name: test\ndata:\n  key: value\n",
        "test",
    );
    assert!(!rows[0].k8s_status);
}

#[test]
fn analyze_reader_no_kind() {
    let rows = analyze_text(
        "apiVersion: v1\nmetadata:\n  name: test\ndata:\n  key: value\n",
        "test",
    );
    assert!(!rows[0].k8s_status);
}

#[test]
fn analyze_reader_insecure_http_in_key() {
    let rows = analyze_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n  namespace: default\ndata:\n  http://example.com: value\n",
        "test",
    );
    assert_eq!(rows[0].insecure_http, 1);
}

#[test]
fn analyze_reader_and_file_agree() {
    let (_d, _p, file_rows) = analyze_str(CLEAN_DEPLOYMENT, false);
    let reader_rows = analyze_text(CLEAN_DEPLOYMENT, "x");
    let strip = |r: &Row| Row {
        dir: String::new(),
        yaml_full_path: String::new(),
        ..r.clone()
    };
    assert_eq!(
        strip(&file_rows[0]),
        strip(&reader_rows[0]),
        "both entry points share analyze_doc"
    );
}
