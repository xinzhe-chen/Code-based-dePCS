use std::fs;
use std::path::Path;

use dzb_core::{ResolvedConfig, RunJson};

pub fn summarize_run(result_dir: &Path) -> Result<String, String> {
    if !result_dir.join("run.json").is_file() {
        return summarize_sweep(result_dir);
    }
    let text = fs::read_to_string(result_dir.join("run.json"))
        .map_err(|error| format!("read run.json failed: {error}"))?;
    let run: RunJson =
        serde_json::from_str(&text).map_err(|error| format!("parse run.json failed: {error}"))?;
    Ok(format!(
        "run_id={} status={} platform={} isolation={} proof_bytes={} protocol_bytes={}",
        run.run_id,
        run.status,
        run.platform,
        run.isolation_tier,
        run.proof_size_bytes,
        run.total_protocol_bytes
    ))
}

fn summarize_sweep(result_dir: &Path) -> Result<String, String> {
    let mut runs = Vec::new();
    collect_runs(result_dir, &mut runs)?;
    if runs.is_empty() {
        return Err(format!("no run.json found under {}", result_dir.display()));
    }
    runs.sort_by(|left, right| left.0.cmp(&right.0));
    let values = runs
        .iter()
        .map(|(path, run, config)| {
            serde_json::json!({
                "path": path.strip_prefix(result_dir).unwrap_or(path),
                "run": run,
                "parameters": config.as_ref().map(|config| &config.original.protocol.parameters),
                "prover_ranks": config.as_ref().map(|config| config.original.roles.prover_ranks),
            })
        })
        .collect::<Vec<_>>();
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 2,
        "run_count": runs.len(),
        "ok_count": runs.iter().filter(|(_, run, _)| run.status == "ok").count(),
        "runs": values,
    }))
    .map_err(|error| error.to_string())?;
    fs::write(result_dir.join("summary.json"), json).map_err(|error| error.to_string())?;

    let mut csv = String::from(
        "path,nv,workers,opening,run_id,status,platform,isolation,proof_bytes,protocol_bytes,prover_ms,verifier_ms\n",
    );
    for (path, run, config) in &runs {
        let parameters = config
            .as_ref()
            .map(|config| &config.original.protocol.parameters);
        let nv = parameters
            .and_then(|parameters| parameters.get("nv"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let opening = parameters
            .and_then(|parameters| parameters.get("opening"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unavailable");
        let workers = config
            .as_ref()
            .map_or(0, |config| config.original.roles.prover_ranks);
        csv.push_str(&format!(
            "{},{nv},{workers},{opening},{},{},{},{},{},{},{:.3},{:.3}\n",
            path.strip_prefix(result_dir).unwrap_or(path).display(),
            run.run_id,
            run.status,
            run.platform,
            run.isolation_tier,
            run.proof_size_bytes,
            run.total_protocol_bytes,
            run.prover_critical_path_ms,
            run.verifier_median_ms,
        ));
    }
    fs::write(result_dir.join("summary.csv"), &csv).map_err(|error| error.to_string())?;
    let rows = csv
        .lines()
        .skip(1)
        .map(|line| {
            format!(
                "<tr>{}</tr>",
                line.split(',')
                    .map(|cell| format!("<td>{cell}</td>"))
                    .collect::<String>()
            )
        })
        .collect::<String>();
    fs::write(
        result_dir.join("summary.html"),
        format!(
            "<!doctype html><meta charset=utf-8><title>DistZKBench sweep</title><h1>DistZKBench measured sweep</h1><p>{} runs; {} ok</p><table><thead><tr><th>path</th><th>nv</th><th>workers</th><th>opening</th><th>run</th><th>status</th><th>platform</th><th>isolation</th><th>proof bytes</th><th>protocol bytes</th><th>prover ms</th><th>verifier ms</th></tr></thead><tbody>{rows}</tbody></table>",
            runs.len(),
            runs.iter().filter(|(_, run, _)| run.status == "ok").count(),
        ),
    )
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "runs={} ok={} summary={}",
        runs.len(),
        runs.iter().filter(|(_, run, _)| run.status == "ok").count(),
        result_dir.join("summary.json").display()
    ))
}

fn collect_runs(
    dir: &Path,
    runs: &mut Vec<(std::path::PathBuf, RunJson, Option<ResolvedConfig>)>,
) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() && path.file_name().is_none_or(|name| name != "warmups") {
            collect_runs(&path, runs)?;
        } else if path.file_name().is_some_and(|name| name == "run.json") {
            let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            let run = serde_json::from_str(&text).map_err(|error| error.to_string())?;
            let run_dir = path.parent().unwrap_or(dir);
            let config = fs::read_to_string(run_dir.join("config.resolved.yaml"))
                .ok()
                .and_then(|text| serde_yaml::from_str(&text).ok());
            runs.push((run_dir.to_path_buf(), run, config));
        }
    }
    Ok(())
}
