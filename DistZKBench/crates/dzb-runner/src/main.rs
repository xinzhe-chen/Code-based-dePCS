use std::env;
use std::fs;

use dzb_runner::{rank_output, run_rank_config_path};
use dzb_sdk::sha256_hex;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("rank") => run_rank(&args[1..]),
        Some("prove") => run_prove(&args[1..]),
        Some("verify") => run_verify(&args[1..]),
        Some(other) => Err(format!("unknown dzb-runner command '{other}'")),
        None => Err("dzb-runner requires a command".to_owned()),
    }
}

fn run_prove(args: &[String]) -> Result<(), String> {
    let config = value_after(args, "--config").ok_or_else(|| "--config is required".to_owned())?;
    run_rank_config_path(std::path::Path::new(&config)).map(|_| ())
}

fn run_rank(args: &[String]) -> Result<(), String> {
    let mut run_id = None;
    let mut rank = None;
    let mut message_bytes = 1024_usize;
    let mut seed = 1_u64;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--run-id" => {
                run_id = args.get(index + 1).cloned();
                index += 2;
            }
            "--rank" => {
                rank = args.get(index + 1).and_then(|value| value.parse().ok());
                index += 2;
            }
            "--message-bytes" => {
                message_bytes = args
                    .get(index + 1)
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| "invalid --message-bytes".to_owned())?;
                index += 2;
            }
            "--seed" => {
                seed = args
                    .get(index + 1)
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| "invalid --seed".to_owned())?;
                index += 2;
            }
            "--out" => {
                out = args.get(index + 1).cloned();
                index += 2;
            }
            other => return Err(format!("unknown rank argument '{other}'")),
        }
    }
    let output = rank_output(
        &run_id.ok_or_else(|| "--run-id is required".to_owned())?,
        rank.ok_or_else(|| "--rank is required".to_owned())?,
        message_bytes,
        seed,
    );
    let text = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    if let Some(path) = out {
        fs::write(path, text).map_err(|error| error.to_string())?;
    } else {
        println!("{text}");
    }
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let mut proof = None;
    let mut sha256 = None;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--proof" => {
                proof = args.get(index + 1).cloned();
                index += 2;
            }
            "--sha256" => {
                sha256 = args.get(index + 1).cloned();
                index += 2;
            }
            "--out" => {
                out = args.get(index + 1).cloned();
                index += 2;
            }
            other => return Err(format!("unknown verify argument '{other}'")),
        }
    }
    let proof_path = proof.ok_or_else(|| "--proof is required".to_owned())?;
    let expected = sha256.ok_or_else(|| "--sha256 is required".to_owned())?;
    let bytes = fs::read(&proof_path).map_err(|error| error.to_string())?;
    let actual = sha256_hex(&bytes);
    let ok = actual == expected;
    let text = serde_json::json!({
        "pid": std::process::id(),
        "proof": proof_path,
        "expected_sha256": expected,
        "actual_sha256": actual,
        "verified": ok,
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
