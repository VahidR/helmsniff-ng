# helmsniff-ng

A Rust CLI that scans rendered Kubernetes/Helm manifests and produces a CSV or
JSON report of security misconfigurations.

`helmsniff-ng` is a 1:1 port of [helmsniff](https://github.com/VahidR/helmsniff)
(Go). Same flags, same 22 columns, byte-identical CSV and JSON output on the
same input, so it is a drop-in replacement in existing pipelines.


I used **Claude Fable 5.1** to port it from `go` to `rust`.

> 📖 **New to helmsniff? Start here:** [**Scanning Helm Charts at Scale with helmsniff**](https://vahid-r.com/posts/helmsniff-tutorial/) — every check explained, with real scans.

## Security Checks

Every output row begins with two context columns, followed by one column per
check. Check columns are binary integers (`1` = violation/detected, `0` = ok),
while `K8S_STATUS` and `HELM_STATUS` are booleans (`true`/`false`).

| Column | Type | Description |
|--------|------|-------------|
| `DIR` | string | Parent directory (chart) path, or input label for stdin mode |
| `YAML_FULL_PATH` | string | Full path to the analyzed YAML file, or input label for stdin mode |
| `WITHIN_MANIFEST_SECRET` | int | Document is a `Secret` with non-empty `data`/`stringData` |
| `VALID_TAINT_SECRET` | int | Reserved for taint-based secret detection (always `0`; not yet implemented) |
| `SEC_CONT_OVER_PRIVIL` | int | A container sets `securityContext.privileged: true` |
| `INSECURE_HTTP` | int | A plaintext `http://` URL found anywhere in the document |
| `NO_SECU_CONTEXT` | int | No `securityContext` at pod level or on any container |
| `NO_DEFAULT_NSPACE` | int | No namespace specified in resource metadata |
| `NO_RESO` | int | A container is missing both resource requests and limits |
| `NO_ROLLING_UPDATE` | int | Deployment uses `Recreate` or lacks a `rollingUpdate` block |
| `NO_NETWORK_POLICY` | int | Chart contains no `NetworkPolicy` resource |
| `TRUE_HOST_PID` | int | `hostPID: true` |
| `TRUE_HOST_IPC` | int | `hostIPC: true` |
| `DOCKERSOCK_PATH` | int | `/var/run/docker.sock` mounted via `hostPath` |
| `TRUE_HOST_NET` | int | `hostNetwork: true` |
| `CAP_SYS_ADMIN` | int | `SYS_ADMIN` capability added to a container |
| `HOST_ALIAS` | int | `hostAliases` present in the pod spec |
| `ALLOW_PRIVI` | int | `allowPrivilegeEscalation: true` |
| `SECCOMP_UNCONFINED` | int | `seccompProfile.type` set to `Unconfined` |
| `CAP_SYS_MODULE` | int | `SYS_MODULE` capability added to a container |
| `K8S_STATUS` | bool | Document is a valid Kubernetes resource (has `apiVersion` and `kind`) |
| `HELM_STATUS` | bool | Document is managed by Helm (`managed-by: Helm` label or `helm.sh/chart` label) |

Pod-level checks look at `spec` (Pod), `spec.template.spec` (Deployment,
StatefulSet, DaemonSet, Job, ReplicaSet, …) and
`spec.jobTemplate.spec.template.spec` (CronJob). Both `containers` and
`initContainers` are inspected.

## Download

Pre-built binaries for Linux (static, musl), Windows and macOS are published on
the [**Releases**](https://github.com/VahidR/helmsniff-ng/releases) page.

```bash
# Linux (amd64, fully static)
curl -L https://github.com/VahidR/helmsniff-ng/releases/latest/download/helmsniff-ng-linux-amd64.tar.gz | tar xz
./helmsniff-ng --root <rendered_dir|-> --out <output_path|->

# macOS (Apple Silicon / arm64)
curl -L https://github.com/VahidR/helmsniff-ng/releases/latest/download/helmsniff-ng-macos-arm64.zip -o helmsniff-ng.zip
unzip helmsniff-ng.zip
```

On Windows, download `helmsniff-ng-windows-amd64.zip` from the Releases page and
extract `helmsniff-ng.exe`.

## Prerequisites

- Rust 1.85+ (`rustup`)
- GNU Make (optional)

## Build

```bash
make build          # or: cargo build --release
```

The binary is compiled to `bin/helmsniff-ng` (and `target/release/helmsniff-ng`).

## Usage

```bash
./bin/helmsniff-ng --root <rendered_dir|-> --out <output_path|-> [--format csv|json]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--root` | Path to directory containing rendered Kubernetes manifests, or `-` to read from stdin |
| `--out` | Path to output file (parent dirs are created), or `-` to write to stdout |
| `--format` | Output format: `csv` (default) or `json` |
| `--help`, `--version` | Usage and version |

**Exit codes:** `0` success · `1` runtime error (stdin unreadable, output not writable) · `2` invalid usage.
A violation does **not** change the exit code; gate on the report instead.

### Batch processing

Scan multiple charts in parallel using GNU `parallel`:

```bash
parallel ./bin/helmsniff-ng --root {} --out reports/{/}.csv ::: datasets/rendered/*/
```

### JSON output

```bash
./bin/helmsniff-ng --root datasets/rendered/mychart --out report.json --format json
```

### Stdin pipe

Pipe `helm template` output directly without writing intermediate files:

```bash
helm template mychart ./charts/mychart | ./bin/helmsniff-ng --root - --out - --format json
```

### CI example (fail on any privileged container)

```bash
helm template mychart ./charts/mychart \
  | helmsniff-ng --root - --out - --format json \
  | jq -e 'map(select(.sec_cont_over_privil == 1)) | length == 0'
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | `cargo build --release` + copy to `bin/` |
| `make clean` | Remove `target/`, `bin/`, `dist/` |
| `make fmt` | `cargo fmt` |
| `make lint` | `cargo fmt --check` + `cargo clippy -D warnings` |
| `make test` | `cargo test` |
| `make dist-linux` | Static musl tarball in `dist/` (needs `rustup target add x86_64-unknown-linux-musl`) |

## Project Structure

```
helmsniff-ng/
├── src/main.rs                        # CLI entry point (clap flags, CSV/JSON output)
├── src/config.rs                      # CSV header definition
├── src/parser.rs                      # Multi-document YAML loader (yaml.v3-compatible rules)
├── src/parser_tests.rs
├── src/scanner/
│   ├── mod.rs                         # File walking & analysis orchestration
│   ├── security_checks.rs             # Individual check implementations
│   ├── row.rs                         # Row data structure + CSV record
│   ├── scanner_tests.rs
│   └── security_checks_tests.rs
├── .github/workflows/ci.yml           # fmt + clippy + test on every push/PR
├── .github/workflows/release.yml      # tag → Linux/Windows/macOS release archives
├── Makefile
└── Cargo.toml
```

## Differences from helmsniff (Go)

| Topic | helmsniff (Go) | helmsniff-ng |
|---|---|---|
| Output | — | byte-identical CSV/JSON (verified on 187 real documents) |
| Empty scan, JSON | `null` | `[]` |
| Unwritable `--out` | panic + stack trace | `error writing output: …`, exit 1 |
| Single-dash flags (`-root`) | accepted | not accepted; use `--root` |
| `--help` / `--version` | no | yes |
| Linux binary | static, ~2.6 MB | static (musl), ~1.1 MB |
| YAML library | `gopkg.in/yaml.v3` (archived upstream) | `serde_yaml_ng` (maintained; same libyaml lineage, so the same parsing rules) |

## Releasing

Releases are automated via GitHub Actions
([`.github/workflows/release.yml`](.github/workflows/release.yml)). Pushing a
semver tag builds the binary for Linux (musl), Windows and macOS and publishes a
GitHub Release with archives and auto-generated release notes:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

[MIT](LICENSE)
