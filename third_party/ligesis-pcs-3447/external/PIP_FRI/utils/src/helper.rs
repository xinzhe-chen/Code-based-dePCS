use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial as UnivariatePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::*;
use std::collections::HashSet;
use std::marker::PhantomData;

use crate::interpolate_vecs_value::QueryVecsResult;
use crate::merkle_tree::MerkleTreeVerifier;
use crate::query_result::QueryResult;

fn batch_bit_reverse(log_n: usize) -> Vec<usize> {
    let n = 1 << log_n;
    let mut res = (0..n).into_iter().map(|_| 0).collect::<Vec<usize>>();
    for i in 0..n {
        res[i] = (res[i >> 1] >> 1) | ((i & 1) << (log_n - 1));
    }
    res
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Helper<T: PrimeField> {
    _field: PhantomData<T>,
}

impl<T: PrimeField> Helper<T> {
    pub fn as_bytes_vec(s: &[T]) -> Vec<u8> {
        let mut res = vec![];
        for i in s {
            res.append(&mut i.into_bigint().to_bytes_be());
        }
        res
    }

    pub fn to_bytes_vec(s: &[T]) -> Vec<u8> {
        let mut res = vec![];
        for i in s {
            res.append(&mut i.into_bigint().to_bytes_be().to_vec());
        }
        res
    }

    pub fn pow(coset: &GeneralEvaluationDomain<T>, index: usize) -> GeneralEvaluationDomain<T> {
        assert_eq!(index & (index - 1), 0);
        let lowbit = (index as i64 & (-(index as i64))) as usize;
        GeneralEvaluationDomain::new_coset(
            coset.size() / lowbit,
            coset.coset_offset().pow([index as u64]),
        )
        .unwrap()
    }

    // use for generate sub-polynomials
    pub fn split_polynomial(
        polynomial: UnivariatePolynomial<T>,
        m: usize,
        l: usize,
    ) -> Vec<UnivariatePolynomial<T>> {
        let coeffs = polynomial.coeffs();
        let mut result = Vec::with_capacity(l);
        for i in 0..l {
            let start = i * m;
            let end = start + m;
            let slice = &coeffs[start..end];
            result.push(UnivariatePolynomial::from_coefficients_slice(&slice));
        }
        result
    }

    pub fn linear_combine(weights: &Vec<T>, vectors: &Vec<Vec<T>>) -> Vec<T> {
        if vectors.is_empty() || weights.is_empty() || vectors[0].is_empty() {
            return vec![];
        }
        let length = vectors[0].len();
        if vectors.iter().any(|v| v.len() != length) || vectors.len() != weights.len() {
            panic!("All vectors must be the same length and match the number of weights.");
        }

        let mut result = vec![T::zero(); length];
        for (weight, vector) in weights.iter().zip(vectors.iter()) {
            for (i, &value) in vector.iter().enumerate() {
                result[i] += *weight * value;
            }
        }
        result
    }

    pub fn verify_query_vecs_results(
        query_vecs_results: &QueryVecsResult<T>,
        tree_root: &[u8; 32],
        leaf_indices: &Vec<usize>,
        leave_number: usize,
    ) -> bool {
        // println!("leave_number: {}", leave_number);
        let merkle_verifier = MerkleTreeVerifier::new(leave_number, &tree_root);
        let leaves_hashes: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|x| {
                Helper::<T>::to_bytes_vec(
                    &[
                        query_vecs_results.proof_values.get(x).unwrap().clone(),
                        query_vecs_results
                            .proof_values
                            .get(&(x + leave_number))
                            .unwrap()
                            .clone(),
                    ]
                    .concat(),
                )
            })
            .collect();

        merkle_verifier.verify(
            query_vecs_results.proof_bytes.clone(),
            &leaf_indices,
            &leaves_hashes,
        )
    }

    pub fn combine_query_vecs_results(
        query_vecs_results: &Vec<QueryVecsResult<T>>,
        sub_tree_roots: &Vec<[u8; 32]>,
        leaf_indices: &Vec<usize>,
        sub_tree_leave_number: usize,
    ) -> QueryVecsResult<T> {
        let n = sub_tree_roots.len();

        let spilted_indices: Vec<Vec<usize>> = (0..n)
            .map(|i| {
                indices_spilt(
                    leaf_indices,
                    i * sub_tree_leave_number,
                    (i + 1) * sub_tree_leave_number,
                )
                .into_iter()
                .map(|x| x - sub_tree_leave_number * i)
                .collect()
            })
            .collect();

        let acc_tree_open_indices: Vec<usize> = spilted_indices
            .iter()
            .enumerate()
            .filter_map(|(i, v)| if v.is_empty() { None } else { Some(i) })
            .collect();

        let (sub_tree_layer_size, _sub_tree_total_size): (Vec<Vec<usize>>, Vec<usize>) =
            spilted_indices
                .iter()
                .map(|indices| get_layer_size(sub_tree_leave_number, indices))
                .collect();

        let combined_proof_bytes = QueryVecsResult::combine_proof_bytes(
            query_vecs_results,
            &sub_tree_layer_size,
            sub_tree_roots,
            acc_tree_open_indices,
        );

        let combined_proof_values =
            QueryVecsResult::combine_proof_values(query_vecs_results, 2 * sub_tree_leave_number);

        QueryVecsResult {
            proof_bytes: combined_proof_bytes,
            proof_values: combined_proof_values,
            vecs_length: query_vecs_results[0].vecs_length,
        }
    }

    pub fn verify_query_results(
        query_results: &QueryResult<T>,
        sub_tree_root: &[u8; 32],
        leaf_indices: &Vec<usize>,
        leave_number: usize,
    ) -> bool {
        let merkle_verifier = MerkleTreeVerifier::new(leave_number, &sub_tree_root);
        let leaves_hashes: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|x| {
                Helper::<T>::to_bytes_vec(&[
                    query_results.proof_values.get(x).unwrap().clone(),
                    query_results
                        .proof_values
                        .get(&(x + leave_number))
                        .unwrap()
                        .clone(),
                ])
            })
            .collect();

        merkle_verifier.verify(
            query_results.proof_bytes.clone(),
            &leaf_indices,
            &leaves_hashes,
        )
    }

    pub fn combine_query_results(
        query_results: &Vec<QueryResult<T>>,
        sub_tree_roots: &Vec<[u8; 32]>,
        leaf_indices: &Vec<usize>,
        sub_tree_leave_number: usize,
    ) -> QueryResult<T> {
        let n = sub_tree_roots.len();

        let spilted_indices: Vec<Vec<usize>> = (0..n)
            .map(|i| {
                indices_spilt(
                    leaf_indices,
                    i * sub_tree_leave_number,
                    (i + 1) * sub_tree_leave_number,
                )
                .into_iter()
                .map(|x| x - sub_tree_leave_number * i)
                .collect()
            })
            .collect();

        let acc_tree_open_indices: Vec<usize> = spilted_indices
            .iter()
            .enumerate()
            .filter_map(|(i, v)| if v.is_empty() { None } else { Some(i) })
            .collect();

        let (sub_tree_layer_size, sub_tree_total_size): (Vec<Vec<usize>>, Vec<usize>) =
            spilted_indices
                .iter()
                .map(|indices| get_layer_size(sub_tree_leave_number, indices))
                .collect();

        for i in 0..n {
            // println!("sub tree id: {}", i);
            assert_eq!(
                query_results[i].proof_bytes.len() / 32,
                sub_tree_total_size[i]
            );
        }

        let combined_proof_bytes = QueryResult::combine_proof_bytes(
            query_results,
            &sub_tree_layer_size,
            sub_tree_roots,
            acc_tree_open_indices,
        );

        let combined_proof_values =
            QueryResult::combine_proof_values(query_results, 2 * sub_tree_leave_number);

        QueryResult {
            proof_bytes: combined_proof_bytes,
            proof_values: combined_proof_values,
        }
    }
}

pub fn nearest_power_of_two(num: usize) -> usize {
    if num.is_power_of_two() {
        return num;
    }

    let mut power_of_two = 1;
    while power_of_two < num {
        power_of_two <<= 1;
    }

    let lower_power_of_two = power_of_two >> 1;
    if num - lower_power_of_two < power_of_two - num {
        lower_power_of_two
    } else {
        power_of_two
    }
}

// get leaf indices from >=start to <end
pub fn indices_spilt(leaf_indices: &Vec<usize>, start: usize, end: usize) -> Vec<usize> {
    leaf_indices
        .iter()
        .filter(|&&index| index >= start && index < end)
        .copied()
        .collect()
}

fn get_layer_size(leave_number: usize, leaf_indices: &Vec<usize>) -> (Vec<usize>, usize) {
    let mut current_level: HashSet<usize> = leaf_indices.iter().cloned().collect();
    let mut result = Vec::new();
    let mut total_nodes = leave_number;
    let mut total_size = 0;

    while total_nodes >= 1 {
        let mut next_level = HashSet::new();
        let mut sibling_nodes = HashSet::new();

        for &index in &current_level {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if sibling_index < total_nodes && !current_level.contains(&sibling_index) {
                sibling_nodes.insert(sibling_index);
            }
            next_level.insert(index / 2);
        }

        if total_nodes >= 2 {
            result.push(sibling_nodes.len());
            total_size += sibling_nodes.len();
        }

        current_level = next_level;
        total_nodes /= 2;
    }

    let num_layer = leave_number.next_power_of_two().trailing_zeros() as usize + 1;
    result.resize(num_layer, 0);

    (result, total_size)
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MultilinearPolynomial<T: PrimeField> {
    coefficients: Vec<T>,
}

impl<T: PrimeField> MultilinearPolynomial<T> {
    pub fn coefficients(&self) -> &Vec<T> {
        &self.coefficients
    }

    pub fn evaluate_hypercube(&self) -> Vec<T> {
        let log_n = self.variable_num();
        let n = self.coefficients.len();
        let rank = batch_bit_reverse(log_n);
        let mut res = self.coefficients.clone();
        for i in 0..n {
            if i < rank[i] {
                (res[i], res[rank[i]]) = (res[rank[i]], res[i]);
            }
        }
        for i in 0..log_n {
            let m = 1 << i;
            for j in (0..n).step_by(m * 2) {
                for k in 0..m {
                    let tmp = res[j + k];
                    res[j + k + m] += tmp;
                }
            }
        }
        res
    }

    pub fn new(coefficients: Vec<T>) -> Self {
        let len = coefficients.len();
        assert_eq!(len & (len - 1), 0);
        MultilinearPolynomial { coefficients }
    }

    pub fn folding(&self, parameter: T) -> Self {
        let coefficients = Self::folding_vector(&self.coefficients, parameter);
        MultilinearPolynomial { coefficients }
    }

    fn folding_vector(v: &Vec<T>, parameter: T) -> Vec<T> {
        let len = v.len();
        assert_eq!(len & (len - 1), 0);
        let mut res = vec![];
        for i in (0..v.len()).step_by(2) {
            res.push(v[i] + parameter * v[i + 1]);
        }
        res
    }

    pub fn rand(variable_num: usize) -> Self {
        let mut rng = rand::thread_rng();
        MultilinearPolynomial {
            coefficients: (0..(1 << variable_num))
                .map(|_| T::rand(&mut rng))
                .collect(),
        }
    }

    // led, evaluate a multilinear polynomial at point
    pub fn evaluate(&self, point: &Vec<T>) -> T {
        let len = self.coefficients.len();
        assert_eq!(1 << point.len(), self.coefficients.len());
        let mut res = self.coefficients.clone();
        for (index, coeff) in point.iter().enumerate() {
            for i in (0..len).step_by(2 << index) {
                let x = *coeff * res[i + (1 << index)];
                res[i] += x;
            }
        }
        res[0]
    }

    // set the coefficient as univariate polynomial coefficient and then evaluate at point
    pub fn evaluate_as_uni_polynomial(&self, point: T) -> T {
        let mut res = T::zero();
        for i in self.coefficients.iter().rev() {
            res *= point;
            res += *i;
        }
        res
    }

    pub fn variable_num(&self) -> usize {
        self.coefficients.len().ilog2() as usize
    }

    // divide into poly_num sub-polynomials
    pub fn chunks(&self, poly_num: usize) -> Vec<MultilinearPolynomial<T>> {
        let chunk_size = self.coefficients.len() / poly_num;
        self.coefficients
            .chunks(chunk_size)
            .map(|sub_poly| Self::new(sub_poly.to_vec()))
            .collect()
    }
}
