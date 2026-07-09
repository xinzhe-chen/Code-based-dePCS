use std::env;
use std::fs;

use dzb_sdk::{Dzb, ProofArtifact, deterministic_bytes, deterministic_seed, sha256_hex};

const TAG_TOY: u32 = 1;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("prove") | None => run_prove(),
        Some("verify") => run_verify(&args[1..]),
        Some(other) => Err(format!("unknown dzb-toy-adapter command '{other}'")),
    }
}

fn run_prove() -> Result<(), String> {
    let mut dzb = dzb_sdk::init()?;
    let adapter = dzb.context().adapter().to_owned();
    match adapter.as_str() {
        "toy-pingpong" => toy_pingpong(&mut dzb)?,
        "toy-alltoall" => toy_alltoall(&mut dzb)?,
        "toy-star-aggregate" | "" => toy_star(&mut dzb)?,
        other => return Err(format!("dzb-toy-adapter does not implement '{other}'")),
    }
    dzb.finish()?;
    Ok(())
}

fn toy_pingpong(dzb: &mut Dzb) -> Result<(), String> {
    if dzb.context().world_size() < 2 {
        return Err("toy-pingpong requires at least two ranks".to_owned());
    }
    let payload = own_payload(dzb);
    dzb.phase("prove.tcp_data_plane", |dzb| {
        if dzb.context().rank() == 0 {
            dzb.send(1, TAG_TOY, &payload)?;
        } else if dzb.context().rank() == 1 {
            dzb.send(0, TAG_TOY, &payload)?;
        }
        Ok(())
    })?;
    if dzb.context().rank() == dzb.context().master_rank() {
        publish_toy_proof(dzb)?;
    }
    Ok(())
}

fn toy_alltoall(dzb: &mut Dzb) -> Result<(), String> {
    let payload = own_payload(dzb);
    dzb.phase("prove.tcp_data_plane", |dzb| {
        let payloads = (0..dzb.context().world_size())
            .map(|_| payload.clone())
            .collect::<Vec<_>>();
        let _ = dzb.all_to_all(TAG_TOY, payloads)?;
        Ok(())
    })?;
    if dzb.context().rank() == dzb.context().master_rank() {
        publish_toy_proof(dzb)?;
    }
    Ok(())
}

fn toy_star(dzb: &mut Dzb) -> Result<(), String> {
    let payload = own_payload(dzb);
    dzb.phase("prove.tcp_data_plane", |dzb| {
        let root = dzb.context().master_rank() as u32;
        let _ = dzb.gather(root, TAG_TOY, &payload)?;
        Ok(())
    })?;
    if dzb.context().rank() == dzb.context().master_rank() {
        publish_toy_proof(dzb)?;
    }
    Ok(())
}

fn own_payload(dzb: &Dzb) -> Vec<u8> {
    deterministic_bytes(
        deterministic_seed(
            dzb.context().config().random_seed,
            dzb.context().run_id(),
            dzb.context().rank(),
            0,
        ),
        dzb.context().config().message_bytes,
    )
}

fn publish_toy_proof(dzb: &mut Dzb) -> Result<ProofArtifact, String> {
    let mut proof_parts = Vec::new();
    for rank in 0..dzb.context().world_size() {
        let seed = deterministic_seed(
            dzb.context().config().random_seed,
            dzb.context().run_id(),
            rank,
            0,
        );
        let bytes = deterministic_bytes(seed, dzb.context().config().message_bytes);
        proof_parts.extend_from_slice(sha256_hex(&bytes).as_bytes());
    }
    let proof = format!(
        "adapter={};run_id={};world_size={};digest={}",
        dzb.context().adapter(),
        dzb.context().run_id(),
        dzb.context().world_size(),
        sha256_hex(&proof_parts)
    );
    dzb.artifacts.publish_proof_bytes(proof.into_bytes())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let proof_path =
        value_after(args, "--proof").ok_or_else(|| "--proof is required".to_owned())?;
    let expected =
        value_after(args, "--sha256").ok_or_else(|| "--sha256 is required".to_owned())?;
    let out = value_after(args, "--out");
    let bytes = fs::read(&proof_path).map_err(|error| error.to_string())?;
    let actual = sha256_hex(&bytes);
    let ok = actual == expected;
    let text = serde_json::json!({
        "pid": std::process::id(),
        "proof": proof_path,
        "expected_sha256": expected,
        "actual_sha256": actual,
        "verified": ok,
        "adapter": "dzb-toy-adapter",
        "thread_budget_env": std::env::var("RAYON_NUM_THREADS").ok(),
        "qos_class": std::env::var("DZB_DARWIN_QOS").ok()
    })
    .to_string();
    if let Some(path) = out {
        fs::write(path, text).map_err(|error| error.to_string())?;
    } else {
        println!("{text}");
    }
    if ok {
        Ok(())
    } else {
        Err("proof sha256 mismatch".to_owned())
    }
}

fn value_after(args: &[String], key: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == key).then(|| pair[1].clone()))
}
