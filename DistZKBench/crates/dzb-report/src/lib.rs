use std::fs;
use std::path::Path;

use dzb_core::RunJson;

pub fn summarize_run(result_dir: &Path) -> Result<String, String> {
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
