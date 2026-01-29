use serde_json::Value;
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() -> anyhow::Result<()> {
    let args = Args::parse()?;

    let project_root = project_root()?;
    let output_path = project_root.join(&args.output);
    let output_md_path = output_path.with_extension("md");
    ensure_parent_dir(&output_path)?;
    ensure_parent_dir(&output_md_path)?;

    let git_sha = git_sha(&project_root)?;
    let timestamp = env::var("BENCH_TIMESTAMP").unwrap_or_else(|_| rfc3339_now());
    let tool_versions = tool_versions(&project_root)?;
    let environment = environment(&tool_versions)?;

    for run in throughput_runs() {
        run_criterion(&project_root, &run)?;
    }

    let mut writer = BufWriter::new(File::create(&output_path)?);
    let mut summary_rows: Vec<SummaryRow> = Vec::new();

    let mut parsed_count = 0usize;
    for run in throughput_runs() {
        for benchmark_id in run.benchmark_ids {
            let estimates_path = criterion_estimates_path(&project_root, benchmark_id);
            let stats = read_criterion_stats_ns(&estimates_path)?;

            let time_ns = stats.mean_ns;
            let ops_per_s = 1e9_f64 / stats.mean_ns;
            let median_ops_per_s = 1e9_f64 / stats.median_ns;

            let size_bytes = benchmark_size_bytes(benchmark_id);
            let artifacts = serde_json::json!({
                "criterion": {
                    "estimates_json": make_relative_path(&project_root, estimates_path.to_string_lossy().as_ref()),
                }
            });

            summary_rows.push(SummaryRow {
                variant: run.variant,
                benchmark_id,
                size_bytes,
                median_ns: stats.median_ns,
                median_ops_per_s,
            });

            for (metric, value, unit) in [
                ("time_ns", time_ns, "ns"),
                ("throughput_ops_per_s", ops_per_s, "ops/s"),
            ] {
                let mut record = serde_json::json!({
                    "schema_version": "v1",
                    "suite": "throughput",
                    "tool": "criterion",
                    "benchmark_id": benchmark_id,
                    "metric": metric,
                    "value": value,
                    "unit": unit,
                    "git_sha": git_sha,
                    "timestamp": timestamp,
                    "environment": environment,
                    "run": {
                        "variant": run.variant,
                        "bench_target": run.bench_target,
                        "cargo": {
                            "no_default_features": run.cargo.no_default_features,
                            "features": run.cargo.features,
                        },
                    },
                    "artifacts": artifacts,
                });

                if let Some(n) = size_bytes {
                    record["input"] = serde_json::json!({ "size_bytes": n });
                }
                record["stats"] = serde_json::json!({
                    "median": {
                        "time_ns": stats.median_ns,
                        "throughput_ops_per_s": median_ops_per_s,
                    }
                });

                writeln!(writer, "{}", serde_json::to_string(&record)?)?;
                parsed_count += 1;
            }
        }
    }

    writer.flush()?;

    if parsed_count == 0 {
        return Err(anyhow::anyhow(
            "parsed 0 criterion benchmarks; did the suite run?",
        ));
    }

    let summary_md = render_summary_markdown(&summary_rows, &git_sha, &timestamp);
    std::fs::write(&output_md_path, summary_md.as_bytes())?;
    println!("{}", summary_md);

    eprintln!("wrote {}", output_path.display());
    eprintln!("wrote {}", output_md_path.display());
    Ok(())
}

struct CriterionStatsNs {
    mean_ns: f64,
    median_ns: f64,
}

fn read_criterion_stats_ns(estimates_path: &Path) -> anyhow::Result<CriterionStatsNs> {
    let f = File::open(estimates_path)?;
    let v: Value = serde_json::from_reader(f)?;
    let mean_ns = v
        .get("mean")
        .and_then(|m| m.get("point_estimate"))
        .and_then(|n| n.as_f64())
        .ok_or_else(|| {
            anyhow::anyhow(format!(
                "missing mean.point_estimate in criterion estimates: {}",
                estimates_path.display()
            ))
        })?;
    let median_ns = v
        .get("median")
        .and_then(|m| m.get("point_estimate"))
        .and_then(|n| n.as_f64())
        .ok_or_else(|| {
            anyhow::anyhow(format!(
                "missing median.point_estimate in criterion estimates: {}",
                estimates_path.display()
            ))
        })?;

    for (label, value) in [("mean", mean_ns), ("median", median_ns)] {
        if value <= 0.0 {
            return Err(anyhow::anyhow(format!(
                "invalid {label}.point_estimate (<= 0): {value} in {}",
                estimates_path.display()
            )));
        }
    }

    Ok(CriterionStatsNs { mean_ns, median_ns })
}

fn criterion_estimates_path(project_root: &Path, benchmark_id: &str) -> PathBuf {
    project_root
        .join("target/criterion")
        .join(benchmark_id)
        .join("new/estimates.json")
}

fn benchmark_size_bytes(benchmark_id: &str) -> Option<u64> {
    let suffix = benchmark_id.rsplit('.').next()?;
    match suffix {
        "0B" => Some(0),
        "32B" => Some(32),
        "256B" => Some(256),
        "1KiB" => Some(1024),
        "16KiB" => Some(16 * 1024),
        _ => None,
    }
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn project_root() -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow("failed to find workspace root"))?;
    Ok(root.to_path_buf())
}

fn git_sha(project_root: &Path) -> anyhow::Result<String> {
    if let Ok(sha) = env::var("GITHUB_SHA") {
        if !sha.trim().is_empty() {
            return Ok(sha);
        }
    }
    let out = Command::new("git")
        .current_dir(project_root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow("git rev-parse HEAD failed"));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn rfc3339_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn rustc_version() -> anyhow::Result<String> {
    let out = Command::new("rustc").arg("-V").output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow("rustc -V failed"));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn environment(tool_versions: &Value) -> anyhow::Result<Value> {
    let runner = match env::var("GITHUB_ACTIONS") {
        Ok(v) if v == "true" => "github-actions",
        _ => "local",
    };

    Ok(serde_json::json!({
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "runner": runner,
        "rustc": rustc_version()?,
        "tools": tool_versions,
    }))
}

fn tool_versions(project_root: &Path) -> anyhow::Result<Value> {
    let criterion = read_lock_version(project_root, "criterion")
        .ok_or_else(|| anyhow::anyhow("failed to detect criterion version from Cargo.lock"))?;

    Ok(serde_json::json!({
        "criterion": criterion,
    }))
}

fn read_lock_version(project_root: &Path, package_name: &str) -> Option<String> {
    let lock_path = project_root.join("Cargo.lock");
    let contents = std::fs::read_to_string(lock_path).ok()?;

    let mut in_pkg = false;
    let mut name: Option<&str> = None;

    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_pkg = true;
            name = None;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = rest.trim().trim_matches('"').into();
            continue;
        }
        if name == Some(package_name) {
            if let Some(rest) = line.strip_prefix("version = ") {
                return Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn make_relative_path(project_root: &Path, path: &str) -> String {
    let project_root = project_root.to_string_lossy();
    if let Some(rel) = path.strip_prefix(project_root.as_ref()) {
        return rel.trim_start_matches('/').to_string();
    }
    path.to_string()
}

#[derive(Clone, Copy)]
struct ThroughputRun {
    variant: &'static str,
    bench_target: &'static str,
    cargo: CargoRun,
    benchmark_ids: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct CargoRun {
    no_default_features: bool,
    features: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct SummaryRow {
    variant: &'static str,
    benchmark_id: &'static str,
    size_bytes: Option<u64>,
    median_ns: f64,
    median_ops_per_s: f64,
}

fn render_summary_markdown(rows: &[SummaryRow], git_sha: &str, timestamp: &str) -> String {
    let mut out = String::new();
    out.push_str("# Throughput Summary\n\n");
    out.push_str(&format!("- git: `{git_sha}`\n"));
    out.push_str(&format!("- timestamp: `{timestamp}`\n\n"));

    let mut rows = rows.to_vec();
    rows.sort_by(|a, b| {
        a.variant
            .cmp(b.variant)
            .then_with(|| a.benchmark_id.cmp(b.benchmark_id))
    });

    let mut current_variant: Option<&'static str> = None;
    for row in rows {
        if current_variant != Some(row.variant) {
            current_variant = Some(row.variant);
            out.push_str(&format!("## variant: {}\n\n", row.variant));
            out.push_str("| benchmark_id | size_bytes | median_time | ops/s |\n");
            out.push_str("| --- | ---: | ---: | ---: |\n");
        }

        let size = row
            .size_bytes
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".to_string());
        let median = format_duration_ns(row.median_ns);
        let ops = format_ops_per_s(row.median_ops_per_s);
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            row.benchmark_id, size, median, ops
        ));
    }

    out.push('\n');
    out
}

fn format_duration_ns(ns: f64) -> String {
    if ns >= 1e9_f64 {
        return format!("{:.3}s", ns / 1e9_f64);
    }
    if ns >= 1e6_f64 {
        return format!("{:.3}ms", ns / 1e6_f64);
    }
    if ns >= 1e3_f64 {
        return format!("{:.3}us", ns / 1e3_f64);
    }
    format!("{:.0}ns", ns)
}

fn format_ops_per_s(ops: f64) -> String {
    if ops < 0.0 {
        return format!("{:.2}", ops);
    }
    if ops < 1e3_f64 {
        return format!("{:.2}", ops);
    }
    if ops < 1e6_f64 {
        return format!("{:.2}k", ops / 1e3_f64);
    }
    if ops < 1e9_f64 {
        return format!("{:.2}M", ops / 1e6_f64);
    }
    if ops < 1e12_f64 {
        return format!("{:.2}G", ops / 1e9_f64);
    }
    if ops < 1e15_f64 {
        return format!("{:.2}T", ops / 1e12_f64);
    }
    format!("{:.2}P", ops / 1e15_f64)
}

fn throughput_runs() -> Vec<ThroughputRun> {
    vec![
        ThroughputRun {
            variant: "default",
            bench_target: "throughput",
            cargo: CargoRun {
                no_default_features: false,
                features: &["resolve", "bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.store.seal_open.direct.1KiB",
                "throughput.store.seal_open.direct.16KiB",
                "throughput.crypto.seal_open.direct.1KiB",
                "throughput.crypto.seal_open.direct.16KiB",
                "throughput.crypto.digest.sha256.32B",
                "throughput.crypto.digest.sha256.1KiB",
                "throughput.crypto.digest.sha256.16KiB",
                "throughput.crypto.digest.blake2b256.32B",
                "throughput.crypto.digest.blake2b256.1KiB",
                "throughput.crypto.digest.blake2b256.16KiB",
                "throughput.cesr.decode_envelope.1KiB",
                "throughput.cesr.decode_envelope.16KiB",
                "throughput.vid.verify.did_peer.offline",
                "throughput.vid.verify.did_web.local",
                "throughput.vid.verify.did_webvh.local",
            ],
        },
        ThroughputRun {
            variant: "transport",
            bench_target: "throughput_transport",
            cargo: CargoRun {
                no_default_features: false,
                features: &["bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.transport.tcp.oneway.deliver.1KiB",
                "throughput.transport.tcp.oneway.deliver.16KiB",
                "throughput.transport.tcp.roundtrip.echo.1KiB",
                "throughput.transport.tcp.roundtrip.echo.16KiB",
                "throughput.transport.tls.oneway.deliver.1KiB",
                "throughput.transport.tls.oneway.deliver.16KiB",
                "throughput.transport.tls.roundtrip.echo.1KiB",
                "throughput.transport.tls.roundtrip.echo.16KiB",
                "throughput.transport.quic.oneway.deliver.1KiB",
                "throughput.transport.quic.roundtrip.echo.1KiB",
            ],
        },
        ThroughputRun {
            variant: "cli",
            bench_target: "throughput_cli",
            cargo: CargoRun {
                no_default_features: false,
                features: &["bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.cli.send_receive.direct.tcp.mem.1KiB",
                "throughput.cli.send_receive.direct.tcp.mem.16KiB",
                "throughput.cli.send_receive.direct.tcp.sqlite.1KiB",
                "throughput.cli.send_receive.direct.tcp.sqlite.16KiB",
                "throughput.cli.relationship.roundtrip.tcp.mem",
                "throughput.cli.relationship.roundtrip.tcp.sqlite",
            ],
        },
        ThroughputRun {
            variant: "store",
            bench_target: "throughput_store_backend",
            cargo: CargoRun {
                no_default_features: false,
                features: &["bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.store.backend.askar.sqlite.persist.wallet_2vid",
                "throughput.store.backend.askar.sqlite.read.wallet_2vid",
            ],
        },
        ThroughputRun {
            variant: "hpke",
            bench_target: "throughput_hpke",
            cargo: CargoRun {
                no_default_features: true,
                features: &["resolve", "bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.crypto.seal_open.hpke.direct.1KiB",
                "throughput.crypto.seal_open.hpke.direct.16KiB",
                "throughput.crypto.sign_verify.ed25519.direct.1KiB",
                "throughput.crypto.sign_verify.ed25519.direct.16KiB",
            ],
        },
        ThroughputRun {
            variant: "pq",
            bench_target: "throughput_pq",
            cargo: CargoRun {
                no_default_features: true,
                features: &["pq", "resolve", "bench-criterion"],
            },
            benchmark_ids: &[
                "throughput.crypto.seal_open.hpke_pq.direct.1KiB",
                "throughput.crypto.seal_open.hpke_pq.direct.16KiB",
                "throughput.crypto.sign_verify.mldsa65.direct.1KiB",
                "throughput.crypto.sign_verify.mldsa65.direct.16KiB",
            ],
        },
    ]
}

fn run_criterion(project_root: &Path, run: &ThroughputRun) -> anyhow::Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);

    cmd.current_dir(project_root)
        .arg("bench")
        .arg("-p")
        .arg("tsp_sdk")
        .arg("--bench")
        .arg(run.bench_target)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if run.cargo.no_default_features {
        cmd.arg("--no-default-features");
    }

    if !run.cargo.features.is_empty() {
        cmd.arg("--features").arg(run.cargo.features.join(","));
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(anyhow::anyhow(format!(
            "{bench} criterion run failed: {status}",
            bench = run.bench_target
        )));
    }

    Ok(())
}

struct Args {
    output: PathBuf,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut output: Option<PathBuf> = None;

        let mut it = env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--output" => {
                    let p = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow("--output requires a value"))?;
                    output = Some(PathBuf::from(p));
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _other => {}
            }
        }

        Ok(Self {
            output: output
                .unwrap_or_else(|| PathBuf::from("target/bench-results/throughput.jsonl")),
        })
    }
}

fn print_help() {
    eprintln!(
        "Usage:\n  cargo bench -p tsp_sdk --bench throughput_report\n  cargo bench -p tsp_sdk --bench throughput_report -- --output <path>\n\n\
Runs the Throughput Suite under criterion and writes canonical JSONL.\n\n\
Args:\n  --output  Output path (default: target/bench-results/throughput.jsonl)\n"
    );
}

mod anyhow {
    pub type Result<T> = std::result::Result<T, Error>;

    pub struct Error(String);

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for Error {}

    pub fn anyhow(msg: impl Into<String>) -> Error {
        Error(msg.into())
    }

    impl From<std::io::Error> for Error {
        fn from(value: std::io::Error) -> Self {
            Error(value.to_string())
        }
    }

    impl From<std::env::VarError> for Error {
        fn from(value: std::env::VarError) -> Self {
            Error(value.to_string())
        }
    }

    impl From<serde_json::Error> for Error {
        fn from(value: serde_json::Error) -> Self {
            Error(value.to_string())
        }
    }

    impl From<std::string::FromUtf8Error> for Error {
        fn from(value: std::string::FromUtf8Error) -> Self {
            Error(value.to_string())
        }
    }
}
