//! helmsniff-ng — statically analyzes pre-rendered Kubernetes/Helm YAML
//! manifests and produces a CSV or JSON report of security misconfigurations.
//!
//! Input modes:
//! - Directory mode (`--root <dir>`): recursively walks rendered manifests,
//!   first checking the whole chart for a NetworkPolicy, then analyzing each
//!   YAML document. Malformed files are skipped so large chart repositories can
//!   be batch-processed.
//! - Stdin mode (`--root -`): reads multi-document YAML from standard input,
//!   e.g. `helm template mychart | helmsniff-ng --root - --out -`.
//!
//! Exit codes: 0 success · 1 runtime error (stdin/output I/O) · 2 invalid usage.

mod config;
mod parser;
mod scanner;

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use scanner::Row;

/// Output format of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Comma-separated values with a header row.
    Csv,
    /// Pretty-printed JSON array of row objects.
    Json,
}

/// Scan rendered Kubernetes/Helm manifests for security misconfigurations.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to the rendered manifests directory, or '-' to read YAML from stdin.
    #[arg(long, value_name = "rendered_dir|-")]
    root: String,

    /// Path to the output file, or '-' to write to stdout.
    #[arg(long, value_name = "path|-")]
    out: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Csv)]
    format: Format,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let rows = match cli.root.as_str() {
        "-" => match scanner::analyze_reader(io::stdin().lock(), "stdin") {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("error reading stdin: {e}");
                return ExitCode::from(1);
            }
        },
        root => scan_directory(root),
    };

    let result = match open_output(&cli.out) {
        Ok(mut w) => match cli.format {
            Format::Json => write_json(&mut w, &rows),
            Format::Csv => write_csv(&mut w, &rows),
        }
        .and_then(|()| w.flush()),
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        eprintln!("error writing output: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Walks `root` and analyzes every YAML file. Files that cannot be read or
/// parsed are skipped silently, matching the Go behaviour for batch scans.
fn scan_directory(root: &str) -> Vec<Row> {
    let has_np = scanner::has_network_policy(root);
    scanner::yaml_files(root)
        .iter()
        .filter_map(|p| scanner::analyze_file(p, root, has_np).ok())
        .flatten()
        .collect()
}

/// Opens the output destination: stdout for `-`, otherwise a file whose
/// parent directories are created on demand.
fn open_output(out: &str) -> io::Result<Box<dyn Write>> {
    if out == "-" {
        return Ok(Box::new(BufWriter::new(io::stdout())));
    }
    if let Some(parent) = Path::new(out).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(Box::new(BufWriter::new(File::create(out)?)))
}

/// Writes the rows as CSV: the `config::CSV_HEADER` row, then one record per
/// row via `Row::to_csv_record`. Check columns are "0"/"1", status columns
/// "true"/"false".
fn write_csv(w: &mut dyn Write, rows: &[Row]) -> io::Result<()> {
    let mut csv = csv::Writer::from_writer(w);
    csv.write_record(config::CSV_HEADER)?;
    for r in rows {
        csv.write_record(r.to_csv_record())?;
    }
    csv.flush()
}

/// Writes the rows as a pretty-printed (2-space) JSON array followed by a
/// newline. An empty scan produces `[]`.
fn write_json(w: &mut dyn Write, rows: &[Row]) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *w, rows)?;
    writeln!(w)
}
