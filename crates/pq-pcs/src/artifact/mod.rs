use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use paper_basefold::{prover as basefold_prover, verifier as basefold_verifier};
use paper_deepfold::{prover as deepfold_prover, verifier as deepfold_verifier};
use paper_util::{
    CODE_RATE as DEFAULT_CODE_RATE, SECURITY_BITS, STEP,
    algebra::{
        coset::Coset,
        field::{MyField, mersenne61_ext::Mersenne61Ext},
        polynomial::MultilinearPolynomial,
    },
    merkle_tree::MERKLE_ROOT_SIZE,
    random_oracle::RandomOracle,
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperPcsBackend {
    BaseFold,
    DeepFold,
}

impl PaperPcsBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseFold => "basefold",
            Self::DeepFold => "deepfold",
        }
    }

    pub const fn scheme_name(self) -> &'static str {
        match self {
            Self::BaseFold => "paper-depcs-basefold",
            Self::DeepFold => "paper-depcs-deepfold",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaperQueryPolicy {
    ArtifactDefault,
    FixedMax,
}

impl PaperQueryPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactDefault => "artifact-default",
            Self::FixedMax => "fixed-max",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PaperPcsRun {
    pub backend: PaperPcsBackend,
    pub nv: usize,
    pub polynomial_length: usize,
    pub code_rate_log: usize,
    pub rate_inv: usize,
    pub security_bits: usize,
    pub query_count: usize,
    pub query_policy: &'static str,
    pub field: &'static str,
    pub hash: &'static str,
    pub source_url: &'static str,
    pub source_rev: &'static str,
    pub license: &'static str,
    pub commit_ms: f64,
    pub open_ms: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
    pub commitment_bytes: usize,
    pub communication_bytes: usize,
    pub verified: bool,
    pub failure_reason: String,
}

pub const PAPER_PCS_SOURCE_URL: &str = "https://github.com/paulguoyanpei/deepfold-bench";
pub const PAPER_PCS_SOURCE_REV: &str = "e4245da33690a9e2afe8f0c1e237b2edde88f6ba";
pub const PAPER_PCS_LICENSE: &str = "NO_LICENSE_FILE_IN_REPOSITORY";
pub const PAPER_PCS_HASH: &str = "Blake3";
pub const PAPER_PCS_SECURITY_BITS: usize = SECURITY_BITS;
pub const PAPER_PCS_DEFAULT_CODE_RATE_LOG: usize = DEFAULT_CODE_RATE;

pub fn paper_query_count(backend: PaperPcsBackend) -> usize {
    paper_query_count_for_code_rate(backend, PAPER_PCS_DEFAULT_CODE_RATE_LOG)
}

pub fn paper_query_count_for_code_rate(backend: PaperPcsBackend, code_rate_log: usize) -> usize {
    match backend {
        PaperPcsBackend::BaseFold => {
            let denominator = (2.0 / (1.0 + 0.5_f32.powi(code_rate_log as i32))).log2();
            (SECURITY_BITS as f32 / denominator).ceil() as usize
        }
        PaperPcsBackend::DeepFold => SECURITY_BITS.div_ceil(code_rate_log.max(1)),
    }
}

pub fn paper_fair_query_count() -> usize {
    paper_query_count(PaperPcsBackend::BaseFold).max(paper_query_count(PaperPcsBackend::DeepFold))
}

pub fn run_paper_pcs(backend: PaperPcsBackend, nv: usize) -> PaperPcsRun {
    run_paper_pcs_with_query_policy(backend, nv, PaperQueryPolicy::ArtifactDefault)
}

pub fn run_paper_pcs_with_query_policy(
    backend: PaperPcsBackend,
    nv: usize,
    query_policy: PaperQueryPolicy,
) -> PaperPcsRun {
    run_paper_pcs_with_options(backend, nv, query_policy, PAPER_PCS_DEFAULT_CODE_RATE_LOG)
}

pub fn run_paper_pcs_with_options(
    backend: PaperPcsBackend,
    nv: usize,
    query_policy: PaperQueryPolicy,
    code_rate_log: usize,
) -> PaperPcsRun {
    match backend {
        PaperPcsBackend::BaseFold => run_basefold::<Mersenne61Ext>(nv, query_policy, code_rate_log),
        PaperPcsBackend::DeepFold => run_deepfold::<Mersenne61Ext>(nv, query_policy, code_rate_log),
    }
}

fn run_basefold<T: MyField>(
    nv: usize,
    query_policy: PaperQueryPolicy,
    code_rate_log: usize,
) -> PaperPcsRun {
    let mut run = base_run(
        PaperPcsBackend::BaseFold,
        nv,
        query_count_for_policy(PaperPcsBackend::BaseFold, query_policy, code_rate_log),
        query_policy,
        code_rate_log,
    );
    let result = catch_unwind(AssertUnwindSafe(|| {
        let polynomial = MultilinearPolynomial::<T>::random_polynomial(nv);
        let interpolate_cosets = interpolate_cosets::<T>(nv, code_rate_log);
        let oracle = RandomOracle::new(nv, run.query_count);

        let commit_start = Instant::now();
        let mut prover =
            basefold_prover::Prover::new(nv, &interpolate_cosets, polynomial, &oracle, STEP);
        let commit = prover.commit_polynomial();
        run.commit_ms = elapsed_ms(commit_start);

        let mut verifier =
            basefold_verifier::Verifier::new(nv, &interpolate_cosets, commit, &oracle, STEP);
        let point = verifier.get_open_point();

        let open_start = Instant::now();
        prover.send_evaluation(&mut verifier, &point);
        prover.prove(&point);
        prover.commit_foldings(&mut verifier);
        let proof = prover.query();
        run.open_ms = elapsed_ms(open_start);

        run.proof_bytes = proof.iter().map(|query| query.proof_size()).sum::<usize>()
            + nv * (MERKLE_ROOT_SIZE + size_of::<T>() * 3);
        run.commitment_bytes = MERKLE_ROOT_SIZE;
        run.communication_bytes = run.commitment_bytes + run.proof_bytes;

        let verify_start = Instant::now();
        run.verified = verifier.verify(&proof);
        run.verify_ms = elapsed_ms(verify_start);
    }));
    if let Err(error) = result {
        run.verified = false;
        run.failure_reason = panic_message(error);
    }
    run
}

fn run_deepfold<T: MyField>(
    nv: usize,
    query_policy: PaperQueryPolicy,
    code_rate_log: usize,
) -> PaperPcsRun {
    let mut run = base_run(
        PaperPcsBackend::DeepFold,
        nv,
        query_count_for_policy(PaperPcsBackend::DeepFold, query_policy, code_rate_log),
        query_policy,
        code_rate_log,
    );
    let result = catch_unwind(AssertUnwindSafe(|| {
        let polynomial = MultilinearPolynomial::<T>::random_polynomial(nv);
        let interpolate_cosets = interpolate_cosets::<T>(nv, code_rate_log);
        let oracle = RandomOracle::new(nv, run.query_count);

        let commit_start = Instant::now();
        let prover = deepfold_prover::Prover::new_with_code_rate(
            nv,
            &interpolate_cosets,
            polynomial,
            &oracle,
            STEP,
            code_rate_log,
        );
        let commit = prover.commit_polynomial();
        run.commit_ms = elapsed_ms(commit_start);

        let verifier =
            deepfold_verifier::Verifier::new(nv, &interpolate_cosets, commit, &oracle, STEP);
        let point = verifier.get_open_point();

        let open_start = Instant::now();
        let proof = prover.generate_proof(point);
        run.open_ms = elapsed_ms(open_start);
        run.proof_bytes = proof.size();
        run.commitment_bytes = MERKLE_ROOT_SIZE + size_of::<T>();
        run.communication_bytes = run.commitment_bytes + run.proof_bytes;

        let verify_start = Instant::now();
        run.verified = verifier.verify(proof);
        run.verify_ms = elapsed_ms(verify_start);
    }));
    if let Err(error) = result {
        run.verified = false;
        run.failure_reason = panic_message(error);
    }
    run
}

fn query_count_for_policy(
    backend: PaperPcsBackend,
    query_policy: PaperQueryPolicy,
    code_rate_log: usize,
) -> usize {
    match query_policy {
        PaperQueryPolicy::ArtifactDefault => {
            paper_query_count_for_code_rate(backend, code_rate_log)
        }
        PaperQueryPolicy::FixedMax => {
            paper_query_count_for_code_rate(PaperPcsBackend::BaseFold, code_rate_log).max(
                paper_query_count_for_code_rate(PaperPcsBackend::DeepFold, code_rate_log),
            )
        }
    }
}

fn base_run(
    backend: PaperPcsBackend,
    nv: usize,
    query_count: usize,
    query_policy: PaperQueryPolicy,
    code_rate_log: usize,
) -> PaperPcsRun {
    PaperPcsRun {
        backend,
        nv,
        polynomial_length: 1_usize << nv,
        code_rate_log,
        rate_inv: 1_usize << code_rate_log,
        security_bits: PAPER_PCS_SECURITY_BITS,
        query_count,
        query_policy: query_policy.as_str(),
        field: Mersenne61Ext::FIELD_NAME,
        hash: PAPER_PCS_HASH,
        source_url: PAPER_PCS_SOURCE_URL,
        source_rev: PAPER_PCS_SOURCE_REV,
        license: PAPER_PCS_LICENSE,
        commit_ms: 0.0,
        open_ms: 0.0,
        verify_ms: 0.0,
        proof_bytes: 0,
        commitment_bytes: 0,
        communication_bytes: 0,
        verified: false,
        failure_reason: String::new(),
    }
}

fn interpolate_cosets<T: MyField>(nv: usize, code_rate_log: usize) -> Vec<Coset<T>> {
    let mut cosets = vec![Coset::new(1 << (nv + code_rate_log), T::from_int(1))];
    for index in 1..=nv {
        cosets.push(cosets[index - 1].pow(2));
    }
    cosets
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn panic_message(error: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = error.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = error.downcast_ref::<String>() {
        message.clone()
    } else {
        "paper PCS verifier panicked".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_basefold_smoke_verifies() {
        let run = run_paper_pcs(PaperPcsBackend::BaseFold, 4);
        assert!(run.verified, "{}", run.failure_reason);
        assert!(run.proof_bytes > 0);
        assert_eq!(
            run.query_count,
            paper_query_count(PaperPcsBackend::BaseFold)
        );
    }

    #[test]
    fn paper_deepfold_smoke_verifies() {
        let run = run_paper_pcs(PaperPcsBackend::DeepFold, 4);
        assert!(run.verified, "{}", run.failure_reason);
        assert!(run.proof_bytes > 0);
        assert_eq!(
            run.query_count,
            paper_query_count(PaperPcsBackend::DeepFold)
        );
    }

    #[test]
    fn paper_fixed_max_query_policy_aligns_backends() {
        let base = run_paper_pcs_with_query_policy(
            PaperPcsBackend::BaseFold,
            4,
            PaperQueryPolicy::FixedMax,
        );
        let deep = run_paper_pcs_with_query_policy(
            PaperPcsBackend::DeepFold,
            4,
            PaperQueryPolicy::FixedMax,
        );
        assert_eq!(base.query_count, deep.query_count);
        assert_eq!(base.query_count, paper_fair_query_count());
    }

    #[test]
    fn paper_deepfold_rate_one_half_smoke_verifies() {
        let run = run_paper_pcs_with_options(
            PaperPcsBackend::DeepFold,
            4,
            PaperQueryPolicy::ArtifactDefault,
            1,
        );
        assert!(run.verified, "{}", run.failure_reason);
        assert_eq!(run.code_rate_log, 1);
        assert_eq!(run.rate_inv, 2);
        assert_eq!(run.query_count, PAPER_PCS_SECURITY_BITS);
    }
}
