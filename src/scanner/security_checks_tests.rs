//! Tests for the individual security checks. Mirrors the Go
//! `security_checks_test.go` tables; fixtures are written as YAML flow text
//! and parsed into `Value` trees, which keeps each case on one line.

use super::*;

/// Parses a YAML snippet into a `Value`.
fn y(s: &str) -> Value {
    serde_yaml_ng::from_str(s).expect("valid test YAML")
}

/// Parses a YAML snippet into a mapping (the test document or pod spec).
fn m(s: &str) -> Mapping {
    match y(s) {
        Value::Mapping(m) => m,
        other => panic!("fixture is not a mapping: {other:?}"),
    }
}

/// Builds a pod spec with one container that has the given securityContext.
fn mk_spec_with_sc(sc: &str) -> Mapping {
    m(&format!(
        "{{containers: [{{name: app, securityContext: {sc}}}]}}"
    ))
}

/// One table row for checks that take a pod spec: `(name, spec, expected)`.
type SpecCase<T> = (&'static str, Option<Mapping>, T);

/// Runs a `(name, spec, want)` table against a check that takes `Option<&Mapping>`.
fn run_spec_table(check: fn(Option<&Mapping>) -> u8, table: &[SpecCase<u8>]) {
    for (name, spec, want) in table {
        assert_eq!(check(spec.as_ref()), *want, "case: {name}");
    }
}

/// Runs a `(name, doc, want)` table against a check that takes `&Mapping`.
fn run_doc_table(check: fn(&Mapping) -> u8, table: &[(&str, Mapping, u8)]) {
    for (name, doc, want) in table {
        assert_eq!(check(doc), *want, "case: {name}");
    }
}

// ---------- helpers ----------

#[test]
fn as_map_cases() {
    assert_eq!(as_map(Some(&y("{a: 1}"))).map(Mapping::len), Some(1));
    assert_eq!(as_map(Some(&y("{}"))).map(Mapping::len), Some(0));
    assert!(as_map(None).is_none());
    assert!(as_map(Some(&y("hello"))).is_none());
    assert!(as_map(Some(&y("42"))).is_none());
    assert!(as_map(Some(&y("[1, 2]"))).is_none());
    assert!(as_map(Some(&y("true"))).is_none());
    assert!(as_map(Some(&Value::Null)).is_none());
}

#[test]
fn as_slice_cases() {
    assert_eq!(as_slice(Some(&y("[1, a]"))).len(), 2);
    assert_eq!(as_slice(Some(&y("[]"))).len(), 0);
    assert!(as_slice(None).is_empty());
    assert!(as_slice(Some(&y("hello"))).is_empty());
    assert!(as_slice(Some(&y("{}"))).is_empty());
    assert!(as_slice(Some(&y("123"))).is_empty());
}

#[test]
fn str_of_cases() {
    assert_eq!(str_of(Some(&y("hello"))), "hello");
    assert_eq!(str_of(Some(&y("\"\""))), "");
    assert_eq!(str_of(None), "");
    assert_eq!(str_of(Some(&y("42"))), "");
    assert_eq!(str_of(Some(&y("true"))), "");
    assert_eq!(str_of(Some(&y("{}"))), "");
}

#[test]
fn bool_of_cases() {
    assert!(bool_of(Some(&y("true"))));
    assert!(!bool_of(Some(&y("false"))));
    assert!(!bool_of(None));
    assert!(!bool_of(Some(&y("\"true\""))));
    assert!(!bool_of(Some(&y("1"))));
    assert!(!bool_of(Some(&y("hello"))));
}

// ---------- has_api_version_and_kind ----------

#[test]
fn has_api_version_and_kind_cases() {
    let table: &[(&str, &str, bool)] = &[
        ("both present", "{apiVersion: v1, kind: Pod}", true),
        ("missing apiVersion", "{kind: Pod}", false),
        ("missing kind", "{apiVersion: v1}", false),
        ("both missing", "{metadata: {}}", false),
        ("empty apiVersion", "{apiVersion: '', kind: Pod}", false),
        ("empty kind", "{apiVersion: v1, kind: ''}", false),
        ("non-string apiVersion", "{apiVersion: 1, kind: Pod}", false),
        ("empty doc", "{}", false),
    ];
    for (name, doc, want) in table {
        assert_eq!(has_api_version_and_kind(&m(doc)), *want, "case: {name}");
    }
}

// ---------- detect_helm_managed ----------

#[test]
fn detect_helm_managed_cases() {
    let table: &[(&str, &str, bool)] = &[
        (
            "managed-by Helm",
            "{metadata: {labels: {app.kubernetes.io/managed-by: Helm}}}",
            true,
        ),
        (
            "helm.sh/chart label present",
            "{metadata: {labels: {helm.sh/chart: myapp-1.0.0}}}",
            true,
        ),
        (
            "both helm labels",
            "{metadata: {labels: {app.kubernetes.io/managed-by: Helm, helm.sh/chart: myapp-1.0.0}}}",
            true,
        ),
        (
            "managed-by not Helm",
            "{metadata: {labels: {app.kubernetes.io/managed-by: kustomize}}}",
            false,
        ),
        ("no labels", "{metadata: {}}", false),
        ("no metadata", "{kind: Pod}", false),
        ("labels not a map", "{metadata: {labels: invalid}}", false),
        ("metadata not a map", "{metadata: invalid}", false),
        (
            "helm.sh/chart null",
            "{metadata: {labels: {helm.sh/chart: null}}}",
            false,
        ),
        ("empty doc", "{}", false),
    ];
    for (name, doc, want) in table {
        assert_eq!(detect_helm_managed(&m(doc)), *want, "case: {name}");
    }
}

// ---------- count_secrets_in_doc ----------

#[test]
fn count_secrets_in_doc_cases() {
    run_doc_table(
        count_secrets_in_doc,
        &[
            (
                "secret with data",
                m("{kind: Secret, data: {key: dmFsdWU=}}"),
                1,
            ),
            (
                "secret with stringData",
                m("{kind: Secret, stringData: {key: value}}"),
                1,
            ),
            (
                "secret with both",
                m("{kind: Secret, data: {a: b}, stringData: {c: d}}"),
                1,
            ),
            ("secret with empty data", m("{kind: Secret, data: {}}"), 0),
            ("secret with no data field", m("{kind: Secret}"), 0),
            (
                "secret case insensitive",
                m("{kind: secret, data: {key: val}}"),
                1,
            ),
            (
                "not a secret",
                m("{kind: ConfigMap, data: {key: value}}"),
                0,
            ),
            ("data not a map", m("{kind: Secret, data: oops}"), 0),
            ("empty doc", m("{}"), 0),
        ],
    );
}

// ---------- has_insecure_http ----------

#[test]
fn has_insecure_http_cases() {
    run_doc_table(
        has_insecure_http,
        &[
            ("http in value", m("{data: {url: 'http://example.com'}}"), 1),
            ("https only", m("{data: {url: 'https://example.com'}}"), 0),
            ("http in key", m("{'http://key': value}"), 1),
            ("http in nested key", m("{outer: {'HTTP://k': 1}}"), 1),
            (
                "http in nested slice",
                m("{items: ['https://safe.com', 'http://insecure.com']}"),
                1,
            ),
            (
                "http deeply nested",
                m("{level1: {level2: {level3: 'http://deep.com'}}}"),
                1,
            ),
            ("case insensitive HTTP", m("{url: 'HTTP://EXAMPLE.COM'}"), 1),
            ("no http anywhere", m("{name: myapp, port: 8080}"), 0),
            ("empty doc", m("{}"), 0),
            ("nil values", m("{key: null}"), 0),
            (
                "http in slice of maps",
                m("{containers: [{env: [{value: 'http://api.local'}]}]}"),
                1,
            ),
            (
                "non-string types only",
                m("{replicas: 3, enabled: true}"),
                0,
            ),
        ],
    );
}

// ---------- containers_from_spec ----------

#[test]
fn containers_from_spec_cases() {
    let table: &[(&str, &str, usize)] = &[
        (
            "containers only",
            "{containers: [{name: app}, {name: sidecar}]}",
            2,
        ),
        ("initContainers only", "{initContainers: [{name: init}]}", 1),
        (
            "both containers and initContainers",
            "{containers: [{name: app}], initContainers: [{name: init}]}",
            2,
        ),
        (
            "template.spec containers",
            "{template: {spec: {containers: [{name: tmpl-app}], initContainers: [{name: tmpl-init}]}}}",
            2,
        ),
        (
            "both direct and template containers",
            "{containers: [{name: direct}], template: {spec: {containers: [{name: tmpl}]}}}",
            2,
        ),
        ("empty containers slice", "{containers: []}", 0),
        ("containers not a list", "{containers: nope}", 0),
        ("no containers at all", "{serviceAccountName: default}", 0),
    ];
    for (name, spec, want) in table {
        assert_eq!(containers_from_spec(&m(spec)).len(), *want, "case: {name}");
    }
}

// ---------- pod_spec_from_doc ----------

#[test]
fn pod_spec_from_doc_cases() {
    // (name, doc, expected key in the returned spec; None = spec must be None)
    let table: &[(&str, &str, Option<&str>)] = &[
        (
            "Pod returns spec directly",
            "{kind: Pod, spec: {containers: []}}",
            Some("containers"),
        ),
        (
            "Deployment returns template.spec",
            "{kind: Deployment, spec: {template: {spec: {hostPID: true}}}}",
            Some("hostPID"),
        ),
        (
            "StatefulSet returns template.spec",
            "{kind: StatefulSet, spec: {template: {spec: {containers: []}}}}",
            Some("containers"),
        ),
        (
            "Service returns none",
            "{kind: Service, spec: {ports: []}}",
            None,
        ),
        (
            "ConfigMap returns none",
            "{kind: ConfigMap, data: {}}",
            None,
        ),
        ("no spec field", "{kind: Deployment}", None),
        (
            "Pod with non-map spec",
            "{kind: Pod, spec: not-a-map}",
            None,
        ),
        (
            "Deployment with no template",
            "{kind: Deployment, spec: {replicas: 3}}",
            None,
        ),
        (
            "CronJob returns jobTemplate.spec.template.spec",
            "{kind: CronJob, spec: {schedule: '0 2 * * *', jobTemplate: {spec: {template: {spec: {hostPID: true}}}}}}",
            Some("hostPID"),
        ),
        (
            "CronJob with jobTemplate but no template",
            "{kind: CronJob, spec: {jobTemplate: {spec: {backoffLimit: 3}}}}",
            None,
        ),
        (
            "CronJob with non-map jobTemplate",
            "{kind: CronJob, spec: {jobTemplate: bad}}",
            None,
        ),
    ];
    for (name, doc, want) in table {
        let doc = m(doc);
        let got = pod_spec_from_doc(&doc);
        match want {
            None => assert!(got.is_none(), "case: {name}: expected None, got {got:?}"),
            Some(key) => {
                let spec = got.unwrap_or_else(|| panic!("case: {name}: expected Some"));
                assert!(spec.contains_key(*key), "case: {name}: missing key {key}");
            }
        }
    }
}

// ---------- lack_security_context ----------

#[test]
fn lack_security_context_cases() {
    run_spec_table(
        lack_security_context,
        &[
            ("nil spec", None, 0),
            (
                "pod-level securityContext present",
                Some(m(
                    "{securityContext: {runAsNonRoot: true}, containers: [{name: app}]}",
                )),
                0,
            ),
            (
                "pod-level securityContext empty map still counts",
                Some(m("{securityContext: {}, containers: [{name: app}]}")),
                0,
            ),
            (
                "pod-level securityContext not a map is ignored",
                Some(m("{securityContext: yes, containers: [{name: app}]}")),
                1,
            ),
            (
                "container-level securityContext present",
                Some(m(
                    "{containers: [{name: app, securityContext: {runAsNonRoot: true}}]}",
                )),
                0,
            ),
            (
                "no securityContext anywhere",
                Some(m("{containers: [{name: app}]}")),
                1,
            ),
            (
                "multiple containers one with securityContext",
                Some(m(
                    "{containers: [{name: app}, {name: sidecar, securityContext: {readOnlyRootFilesystem: true}}]}",
                )),
                0,
            ),
            (
                "multiple containers none with securityContext",
                Some(m("{containers: [{name: app}, {name: sidecar}]}")),
                1,
            ),
            (
                "container securityContext null does not count",
                Some(m("{containers: [{name: app, securityContext: null}]}")),
                1,
            ),
            ("no containers", Some(m("{serviceAccountName: default}")), 0),
            ("empty containers slice", Some(m("{containers: []}")), 0),
        ],
    );
}

// ---------- lack_resources ----------

#[test]
fn lack_resources_cases() {
    run_spec_table(
        lack_resources,
        &[
            ("nil spec", None, 0),
            (
                "has limits",
                Some(m(
                    "{containers: [{name: app, resources: {limits: {cpu: 100m}}}]}",
                )),
                0,
            ),
            (
                "has requests",
                Some(m(
                    "{containers: [{name: app, resources: {requests: {memory: 64Mi}}}]}",
                )),
                0,
            ),
            (
                "has both",
                Some(m(
                    "{containers: [{name: app, resources: {limits: {cpu: 100m}, requests: {cpu: 50m}}}]}",
                )),
                0,
            ),
            (
                "no resources at all",
                Some(m("{containers: [{name: app}]}")),
                1,
            ),
            (
                "empty resources map",
                Some(m("{containers: [{name: app, resources: {}}]}")),
                1,
            ),
            (
                "one container ok one missing",
                Some(m(
                    "{containers: [{name: app, resources: {limits: {cpu: 100m}}}, {name: sidecar}]}",
                )),
                1,
            ),
            ("no containers", Some(m("{serviceAccountName: default}")), 0),
            ("empty containers slice", Some(m("{containers: []}")), 0),
            (
                "empty limits and requests",
                Some(m(
                    "{containers: [{name: app, resources: {limits: {}, requests: {}}}]}",
                )),
                1,
            ),
        ],
    );
}

// ---------- check_host_flags ----------

#[test]
fn check_host_flags_cases() {
    let table: &[SpecCase<(u8, u8, u8)>] = &[
        ("nil spec", None, (0, 0, 0)),
        (
            "all true",
            Some(m("{hostPID: true, hostIPC: true, hostNetwork: true}")),
            (1, 1, 1),
        ),
        (
            "all false",
            Some(m("{hostPID: false, hostIPC: false, hostNetwork: false}")),
            (0, 0, 0),
        ),
        ("only hostPID", Some(m("{hostPID: true}")), (1, 0, 0)),
        ("only hostIPC", Some(m("{hostIPC: true}")), (0, 1, 0)),
        (
            "only hostNetwork",
            Some(m("{hostNetwork: true}")),
            (0, 0, 1),
        ),
        (
            "non-bool values",
            Some(m("{hostPID: 'true', hostIPC: 1, hostNetwork: yes}")),
            (0, 0, 0),
        ),
        ("fields not present", Some(m("{containers: []}")), (0, 0, 0)),
    ];
    for (name, spec, want) in table {
        assert_eq!(check_host_flags(spec.as_ref()), *want, "case: {name}");
    }
}

// ---------- check_docker_sock ----------

#[test]
fn check_docker_sock_cases() {
    run_spec_table(
        check_docker_sock,
        &[
            ("nil spec", None, 0),
            (
                "docker sock mounted",
                Some(m(
                    "{volumes: [{name: docker, hostPath: {path: /var/run/docker.sock}}]}",
                )),
                1,
            ),
            (
                "docker sock in subpath",
                Some(m(
                    "{volumes: [{name: docker, hostPath: {path: /host/var/run/docker.sock}}]}",
                )),
                1,
            ),
            (
                "no docker sock",
                Some(m("{volumes: [{name: data, hostPath: {path: /var/data}}]}")),
                0,
            ),
            ("no volumes", Some(m("{containers: []}")), 0),
            (
                "volume without hostPath",
                Some(m(
                    "{volumes: [{name: config, configMap: {name: my-config}}]}",
                )),
                0,
            ),
            (
                "multiple volumes one with docker sock",
                Some(m(
                    "{volumes: [{name: data, hostPath: {path: /var/data}}, {name: docker, hostPath: {path: /var/run/docker.sock}}]}",
                )),
                1,
            ),
            ("empty volumes", Some(m("{volumes: []}")), 0),
            (
                "volume entry not a map",
                Some(m("{volumes: [just-a-string]}")),
                0,
            ),
        ],
    );
}

// ---------- check_caps ----------

#[test]
fn check_caps_cases() {
    let table: &[SpecCase<(u8, u8, u8, u8)>] = &[
        ("nil spec", None, (0, 0, 0, 0)),
        (
            "SYS_ADMIN capability",
            Some(mk_spec_with_sc("{capabilities: {add: [SYS_ADMIN]}}")),
            (1, 0, 0, 0),
        ),
        (
            "SYS_MODULE capability",
            Some(mk_spec_with_sc("{capabilities: {add: [SYS_MODULE]}}")),
            (0, 1, 0, 0),
        ),
        (
            "both SYS_ADMIN and SYS_MODULE",
            Some(mk_spec_with_sc(
                "{capabilities: {add: [SYS_ADMIN, SYS_MODULE]}}",
            )),
            (1, 1, 0, 0),
        ),
        (
            "allowPrivilegeEscalation",
            Some(mk_spec_with_sc("{allowPrivilegeEscalation: true}")),
            (0, 0, 1, 0),
        ),
        (
            "seccomp Unconfined",
            Some(mk_spec_with_sc("{seccompProfile: {type: Unconfined}}")),
            (0, 0, 0, 1),
        ),
        (
            "seccomp unconfined lowercase",
            Some(mk_spec_with_sc("{seccompProfile: {type: unconfined}}")),
            (0, 0, 0, 1),
        ),
        (
            "all violations",
            Some(mk_spec_with_sc(
                "{capabilities: {add: [SYS_ADMIN, SYS_MODULE]}, allowPrivilegeEscalation: true, seccompProfile: {type: Unconfined}}",
            )),
            (1, 1, 1, 1),
        ),
        (
            "no violations",
            Some(mk_spec_with_sc(
                "{capabilities: {add: [NET_BIND_SERVICE]}, allowPrivilegeEscalation: false, seccompProfile: {type: RuntimeDefault}}",
            )),
            (0, 0, 0, 0),
        ),
        (
            "no securityContext on container",
            Some(m("{containers: [{name: app}]}")),
            (0, 0, 0, 0),
        ),
        (
            "caps lowercase",
            Some(mk_spec_with_sc(
                "{capabilities: {add: [sys_admin, sys_module]}}",
            )),
            (1, 1, 0, 0),
        ),
        (
            "multiple containers mixed",
            Some(m(
                "{containers: [{name: safe, securityContext: {allowPrivilegeEscalation: false}}, {name: dangerous, securityContext: {allowPrivilegeEscalation: true, capabilities: {add: [SYS_ADMIN]}}}]}",
            )),
            (1, 0, 1, 0),
        ),
        (
            "empty add list",
            Some(mk_spec_with_sc("{capabilities: {add: []}}")),
            (0, 0, 0, 0),
        ),
        (
            "non-string cap entries ignored",
            Some(mk_spec_with_sc("{capabilities: {add: [1, null, {x: y}]}}")),
            (0, 0, 0, 0),
        ),
    ];
    for (name, spec, want) in table {
        assert_eq!(check_caps(spec.as_ref()), *want, "case: {name}");
    }
}

// ---------- check_privileged ----------

#[test]
fn check_privileged_cases() {
    run_spec_table(
        check_privileged,
        &[
            ("nil spec", None, 0),
            ("no containers", Some(m("{}")), 0),
            (
                "container without securityContext",
                Some(m("{containers: [{name: app}]}")),
                0,
            ),
            (
                "privileged false",
                Some(mk_spec_with_sc("{privileged: false}")),
                0,
            ),
            (
                "privileged true",
                Some(mk_spec_with_sc("{privileged: true}")),
                1,
            ),
            (
                "privileged as string is ignored",
                Some(mk_spec_with_sc("{privileged: 'true'}")),
                0,
            ),
            (
                "privileged initContainer",
                Some(m(
                    "{containers: [{name: app}], initContainers: [{name: init, securityContext: {privileged: true}}]}",
                )),
                1,
            ),
            (
                "one of many containers privileged",
                Some(m(
                    "{containers: [{name: a, securityContext: {privileged: false}}, {name: b, securityContext: {privileged: true}}]}",
                )),
                1,
            ),
            (
                "pod-level securityContext.privileged is not a container flag",
                Some(m(
                    "{securityContext: {privileged: true}, containers: [{name: app}]}",
                )),
                0,
            ),
        ],
    );
}

// ---------- has_host_aliases ----------

#[test]
fn has_host_aliases_cases() {
    run_spec_table(
        has_host_aliases,
        &[
            ("nil spec", None, 0),
            (
                "hostAliases present",
                Some(m("{hostAliases: [{ip: 1.2.3.4, hostnames: [evil.com]}]}")),
                1,
            ),
            ("empty hostAliases", Some(m("{hostAliases: []}")), 0),
            ("no hostAliases field", Some(m("{containers: []}")), 0),
            (
                "hostAliases not a slice",
                Some(m("{hostAliases: not-a-slice}")),
                0,
            ),
            (
                "multiple hostAliases",
                Some(m("{hostAliases: [{ip: 1.1.1.1}, {ip: 2.2.2.2}]}")),
                1,
            ),
        ],
    );
}

// ---------- lack_rolling_update ----------

#[test]
fn lack_rolling_update_cases() {
    run_doc_table(
        lack_rolling_update,
        &[
            (
                "Deployment with RollingUpdate configured",
                m(
                    "{kind: Deployment, spec: {strategy: {type: RollingUpdate, rollingUpdate: {maxSurge: 1, maxUnavailable: 0}}}}",
                ),
                0,
            ),
            (
                "Deployment with Recreate strategy",
                m("{kind: Deployment, spec: {strategy: {type: Recreate}}}"),
                1,
            ),
            (
                "Deployment with no rollingUpdate config",
                m("{kind: Deployment, spec: {strategy: {type: RollingUpdate}}}"),
                1,
            ),
            (
                "Deployment with no strategy at all",
                m("{kind: Deployment, spec: {}}"),
                1,
            ),
            ("Deployment with nil spec", m("{kind: Deployment}"), 1),
            (
                "Deployment with rollingUpdate not a map",
                m("{kind: Deployment, spec: {strategy: {rollingUpdate: yes}}}"),
                1,
            ),
            (
                "Deployment with empty rollingUpdate map",
                m("{kind: Deployment, spec: {strategy: {rollingUpdate: {}}}}"),
                0,
            ),
            (
                "StatefulSet (not Deployment)",
                m("{kind: StatefulSet, spec: {}}"),
                0,
            ),
            ("Service (not Deployment)", m("{kind: Service}"), 0),
            ("empty doc", m("{}"), 0),
            ("deployment lowercase", m("{kind: deployment, spec: {}}"), 1),
            (
                "recreate lowercase",
                m("{kind: Deployment, spec: {strategy: {type: recreate}}}"),
                1,
            ),
        ],
    );
}

// ---------- lack_namespace ----------

#[test]
fn lack_namespace_cases() {
    run_doc_table(
        lack_namespace,
        &[
            (
                "namespace present",
                m("{metadata: {namespace: production}}"),
                0,
            ),
            ("namespace empty", m("{metadata: {namespace: ''}}"), 1),
            ("no namespace field", m("{metadata: {name: myapp}}"), 1),
            ("no metadata", m("{kind: Pod}"), 1),
            ("metadata not a map", m("{metadata: invalid}"), 1),
            (
                "namespace is non-string",
                m("{metadata: {namespace: 123}}"),
                1,
            ),
            ("empty doc", m("{}"), 1),
        ],
    );
}
