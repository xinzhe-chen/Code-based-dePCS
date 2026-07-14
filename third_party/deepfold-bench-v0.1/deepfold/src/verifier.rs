use crate::{Commit, Proof};
use util::random_oracle::RandomOracle;
use util::{
    algebra::{coset::Coset, field::MyField},
    merkle_tree::MerkleTreeVerifier,
    query_result::QueryResult,
};

#[derive(Clone)]
pub struct Verifier<T: MyField> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    polynomial_roots: Vec<MerkleTreeVerifier>,
    first_deep: T,
    oracle: RandomOracle<T>,
    open_point: Vec<T>,
    step: usize,
}

impl<T: MyField> Verifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<Coset<T>>,
        commit: Commit<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        Verifier {
            total_round,
            interpolate_cosets: coset.clone(),
            oracle: oracle.clone(),
            polynomial_roots: vec![MerkleTreeVerifier::new(
                coset[0].size() / (1 << step), // todo: 2?
                &commit.merkle_root,
            )],
            first_deep: commit.deep,
            open_point: (0..total_round).map(|_| T::random_element()).collect(),
            step,
        }
    }

    pub fn get_open_point(&self) -> Vec<T> {
        self.open_point.clone()
    }

    pub fn set_open_point(&mut self, point: &[T]) {
        self.open_point = point.to_vec();
    }

    pub fn verify(self, proof: Proof<T>) -> bool {
        self.verify_ref(&proof)
    }

    pub fn verify_ref(mut self, proof: &Proof<T>) -> bool {
        let mut leave_number = self.interpolate_cosets[0].size() / (1 << self.step);
        for merkle_root in &proof.merkle_root {
            leave_number /= 1 << self.step;
            self.polynomial_roots.push(MerkleTreeVerifier {
                merkle_root: *merkle_root,
                leave_number,
            });
        }
        assert_eq!(self.first_deep, proof.deep_evals[0].0);
        self._verify(proof)
    }

    fn _verify(&self, proof: &Proof<T>) -> bool {
        let polynomial_proof = &proof.query_result;
        let mut leaf_indices = self.oracle.query_list.clone();
        let leaf_size = 1 << self.step;
        let mut li = self.oracle.query_list.clone();
        let mut layer_indices: Vec<Vec<usize>> = Vec::with_capacity(polynomial_proof.len());
        let mut layer_lens: Vec<usize> = Vec::with_capacity(polynomial_proof.len());
        let mut inv_cache = (0..self.interpolate_cosets.len())
            .map(|_| Vec::<(usize, T)>::new())
            .collect::<Vec<_>>();
        for layer in 0..polynomial_proof.len() {
            let len = self.interpolate_cosets[layer * self.step].size() >> self.step;
            for idx in &mut li {
                *idx %= len;
            }
            li.sort_unstable();
            li.dedup();
            polynomial_proof[layer].assert_canonical_len(&li, leaf_size);
            layer_lens.push(len);
            layer_indices.push(li.clone());
        }
        for i in 0..self.total_round / self.step {
            let domain_size = self.interpolate_cosets[i * self.step].size();
            let leaf_domain_size = domain_size / leaf_size;
            for idx in &mut leaf_indices {
                *idx %= leaf_domain_size;
            }
            leaf_indices.sort_unstable();
            leaf_indices.dedup();

            polynomial_proof[i].verify_merkle_tree(
                &leaf_indices,
                1 << self.step,
                &self.polynomial_roots[i],
            );

            if i == self.total_round / self.step - 1 {
                let challenges = &self.oracle.folding_challenges[0..self.total_round];
                assert_eq!(
                    verify_eval_from_points(
                        self.open_point.iter().copied(),
                        self.open_point.len(),
                        proof.evaluation,
                        &proof.shuffle_evals,
                        challenges,
                    ),
                    proof.final_value
                );
                for (idx, (first_eval, else_evals)) in proof.deep_evals.iter().enumerate() {
                    let point_len = self.total_round - idx;
                    assert_eq!(
                        verify_eval_from_points(
                            std::iter::successors(Some(self.oracle.deep[idx]), |&x| Some(x * x))
                                .take(point_len),
                            point_len,
                            *first_eval,
                            else_evals,
                            challenges,
                        ),
                        proof.final_value
                    );
                }
            }

            if self.step == 1 {
                verify_step_one_layer(
                    polynomial_proof,
                    &layer_indices,
                    &layer_lens,
                    &mut inv_cache,
                    &self.interpolate_cosets,
                    &self.oracle.folding_challenges,
                    i,
                    leaf_size,
                    domain_size,
                    &leaf_indices,
                );
                continue;
            }

            let challenge = &self.oracle.folding_challenges[i * self.step..(i + 1) * self.step];
            let mut verify_values = Vec::with_capacity(1 << self.step);
            let mut verify_inds = Vec::with_capacity(1 << self.step);
            let mut tmp_values = Vec::with_capacity(1 << self.step);
            let mut tmp_inds = Vec::with_capacity(1 << self.step);
            for k in &leaf_indices {
                verify_values.clear();
                verify_inds.clear();
                for j in 0..(1 << self.step) {
                    // Init verify values, which is the total values in the first step
                    let ind = k + j * domain_size / (1 << self.step);
                    verify_values.push(polynomial_proof[i].value_at(
                        &layer_indices[i],
                        leaf_size,
                        layer_lens[i],
                        ind,
                    ));
                    verify_inds.push(ind);
                }
                for j in 0..self.step {
                    let coset_idx = i * self.step + j;
                    let size = verify_values.len();
                    tmp_values.clear();
                    tmp_inds.clear();
                    for l in 0..size / 2 {
                        let x = verify_values[l];
                        let nx = verify_values[l + size / 2];
                        let coset_inv = cached_element_inv(
                            &mut inv_cache[coset_idx],
                            &self.interpolate_cosets[coset_idx],
                            verify_inds[l],
                        );
                        tmp_values
                            .push((x + nx + challenge[j] * (x - nx) * coset_inv) * T::inverse_2());
                        tmp_inds.push(verify_inds[l]);
                    }
                    std::mem::swap(&mut verify_values, &mut tmp_values);
                    std::mem::swap(&mut verify_inds, &mut tmp_inds);
                }
                assert_eq!(
                    verify_values[0],
                    polynomial_proof[i + 1].value_at(
                        &layer_indices[i + 1],
                        leaf_size,
                        layer_lens[i + 1],
                        *k,
                    )
                );
            }
        }
        true
    }
}

fn cached_element_inv<T: MyField>(
    cache: &mut Vec<(usize, T)>,
    coset: &Coset<T>,
    index: usize,
) -> T {
    if let Some((_, value)) = cache
        .iter()
        .find(|(cached_index, _)| *cached_index == index)
    {
        return *value;
    }
    let value = coset.element_inv_at(index);
    cache.push((index, value));
    value
}

fn verify_eval_from_points<T, I>(
    points: I,
    point_len: usize,
    first_eval: T,
    else_evals: &[T],
    challenges: &[T],
) -> T
where
    T: MyField,
    I: Iterator<Item = T>,
{
    let challenges = &challenges[challenges.len() - point_len..];
    let mut y_0 = first_eval;
    assert_eq!(point_len, else_evals.len());
    for ((x, eval), challenge) in points.zip(else_evals.iter()).zip(challenges.iter()) {
        let y_1 = *eval;
        y_0 += (y_1 - y_0) * (*challenge - x);
    }
    y_0
}

fn verify_step_one_layer<T: MyField>(
    polynomial_proof: &[QueryResult<T>],
    layer_indices: &[Vec<usize>],
    layer_lens: &[usize],
    inv_cache: &mut [Vec<(usize, T)>],
    interpolate_cosets: &[Coset<T>],
    folding_challenges: &[T],
    layer: usize,
    leaf_size: usize,
    domain_size: usize,
    leaf_indices: &[usize],
) {
    let half_domain = domain_size / 2;
    let challenge = folding_challenges[layer];
    for k in leaf_indices {
        let x = polynomial_proof[layer].value_at(
            &layer_indices[layer],
            leaf_size,
            layer_lens[layer],
            *k,
        );
        let nx = polynomial_proof[layer].value_at(
            &layer_indices[layer],
            leaf_size,
            layer_lens[layer],
            *k + half_domain,
        );
        let coset_inv = cached_element_inv(&mut inv_cache[layer], &interpolate_cosets[layer], *k);
        let folded = (x + nx + challenge * (x - nx) * coset_inv) * T::inverse_2();
        assert_eq!(
            folded,
            polynomial_proof[layer + 1].value_at(
                &layer_indices[layer + 1],
                leaf_size,
                layer_lens[layer + 1],
                *k,
            )
        );
    }
}
