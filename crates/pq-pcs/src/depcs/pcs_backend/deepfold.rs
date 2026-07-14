//! DeepFold PCS backend adapter for artifact-backed dePCS.
//!
//! This module is the only dePCS layer that talks directly to the vendored
//! `paper_deepfold` prover/verifier API. Protocol 6-11 code calls through
//! `pcs_backend::mod` and never depends on DeepFold artifact internals.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use paper_deepfold::{self, prover as deepfold_prover, verifier as deepfold_verifier};
use paper_util::algebra::coset::Coset;
use paper_util::{STEP, algebra::polynomial::MultilinearPolynomial, random_oracle::RandomOracle};

use super::{interpolate_cosets, interpolate_cosets_lazy};
use crate::depcs::types::*;

type LazyCosetCache = Mutex<HashMap<(usize, usize), Arc<Vec<Coset<PaperField>>>>>;
type MaterializedCosetEntry = ((usize, usize), Arc<Vec<Coset<PaperField>>>);
const MATERIALIZED_COSET_CACHE_CAPACITY: usize = 2;

#[derive(Default)]
struct BoundedMaterializedCosetCache {
    entries: VecDeque<MaterializedCosetEntry>,
}

impl BoundedMaterializedCosetCache {
    fn get_or_insert_with<F>(
        &mut self,
        key: (usize, usize),
        build: F,
    ) -> Arc<Vec<Coset<PaperField>>>
    where
        F: FnOnce() -> Vec<Coset<PaperField>>,
    {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|(entry_key, _)| *entry_key == key)
        {
            let (_, value) = self.entries.remove(pos).expect("cache position exists");
            let result = value.clone();
            self.entries.push_back((key, value));
            return result;
        }
        let value = Arc::new(build());
        self.entries.push_back((key, value.clone()));
        while self.entries.len() > MATERIALIZED_COSET_CACHE_CAPACITY {
            self.entries.pop_front();
        }
        value
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

type MaterializedCosetCache = Mutex<BoundedMaterializedCosetCache>;

fn lazy_coset_cache() -> &'static LazyCosetCache {
    static CACHE: OnceLock<LazyCosetCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn materialized_coset_cache() -> &'static MaterializedCosetCache {
    static CACHE: OnceLock<MaterializedCosetCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedMaterializedCosetCache::default()))
}

fn cached_lazy_cosets(nv: usize, code_rate_log: usize) -> Arc<Vec<Coset<PaperField>>> {
    let key = (nv, code_rate_log);
    let mut cache = match lazy_coset_cache().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    cache
        .entry(key)
        .or_insert_with(|| Arc::new(interpolate_cosets_lazy(nv, code_rate_log)))
        .clone()
}

pub(crate) fn cached_materialized_cosets(
    nv: usize,
    code_rate_log: usize,
) -> Arc<Vec<Coset<PaperField>>> {
    let key = (nv, code_rate_log);
    let mut cache = match materialized_coset_cache().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    cache.get_or_insert_with(key, || interpolate_cosets(nv, code_rate_log))
}

pub(crate) fn prepare_prover(
    nv: usize,
    values: Vec<PaperField>,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> deepfold_prover::Prover<PaperField> {
    let polynomial = MultilinearPolynomial::new(values);
    let cosets = cached_materialized_cosets(nv, code_rate_log);
    deepfold_prover::Prover::new_with_code_rate_shared(
        nv,
        cosets,
        polynomial,
        oracle,
        STEP,
        code_rate_log,
    )
}

pub(crate) fn open_polynomial(
    nv: usize,
    values: Vec<PaperField>,
    point: &[PaperField],
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> (PaperPcsOpeningProof, PaperField) {
    let prover = prepare_prover(nv, values, oracle, code_rate_log);
    let proof = prover.generate_proof(point.to_vec());
    let evaluation = proof.evaluation;
    (PaperPcsOpeningProof::DeepFold(proof), evaluation)
}

pub(crate) fn verify_evaluation(
    nv: usize,
    commitment: &paper_deepfold::Commit<PaperField>,
    point: &[PaperField],
    value: PaperField,
    proof: &paper_deepfold::Proof<PaperField>,
    oracle: &RandomOracle<PaperField>,
    code_rate_log: usize,
) -> bool {
    let cosets = cached_lazy_cosets(nv, code_rate_log);
    let mut verifier =
        deepfold_verifier::Verifier::new(nv, cosets.as_ref(), commitment.clone(), oracle, STEP);
    verifier.set_open_point(point);
    verifier.verify_ref(proof) && proof.evaluation == value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialized_coset_cache_reuses_same_key() {
        let mut cache = BoundedMaterializedCosetCache::default();
        let first = cache.get_or_insert_with((6, 1), || interpolate_cosets(6, 1));
        let second = cache.get_or_insert_with((6, 1), || interpolate_cosets(6, 1));
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn materialized_coset_cache_evicts_oldest_but_held_arc_survives() {
        let mut cache = BoundedMaterializedCosetCache::default();
        let held = cache.get_or_insert_with((6, 1), || interpolate_cosets(6, 1));
        let _second = cache.get_or_insert_with((7, 1), || interpolate_cosets(7, 1));
        let _third = cache.get_or_insert_with((8, 1), || interpolate_cosets(8, 1));
        assert_eq!(cache.len(), MATERIALIZED_COSET_CACHE_CAPACITY);
        assert_eq!(held[0].size(), 1 << 7);

        let rebuilt = cache.get_or_insert_with((6, 1), || interpolate_cosets(6, 1));
        assert!(!Arc::ptr_eq(&held, &rebuilt));
        assert_eq!(rebuilt[0].size(), held[0].size());
    }
}
