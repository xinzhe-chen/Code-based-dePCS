use crate::verifier::BatchFRIVerifier;
// use std::sync::Exclusive;
use ark_ff::PrimeField;
use ark_poly::polynomial::univariate::DensePolynomial as UnivariatePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer};
use de_network::{DeMultiNet as Net, DeNet, DeSerNet};
use rs_merkle::MerkleTree;
use std::collections::HashSet;
use std::time::Instant;
use utils::helper::Helper;
use utils::interpolate_vecs_value::{InterpolateVecsValue, QueryVecsResult, QueryVecsResultTest};
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::merkle_tree::{Blake3Algorithm, MerkleTreeVerifier};
use utils::query_result::{QueryResult, QueryResultTest};
use utils::{commit_open_vec::ComOpenOneVec, fiat_shamir::RandomOracle};
use utils::{CODE_RATE, SECURITY_BITS};

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

// get leaf indices from >=start to <end
pub fn indices_spilt(leaf_indices: &Vec<usize>, start: usize, end: usize) -> Vec<usize> {
    leaf_indices
        .iter()
        .filter(|&&index| index >= start && index < end)
        .copied()
        .collect()
}

pub fn verify_query_vecs_results<T: PrimeField>(
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

pub fn verify_query_results<T: PrimeField>(
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

pub fn combine_query_vecs_results<T: PrimeField>(
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

pub fn combine_query_results<T: PrimeField>(
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

    let (sub_tree_layer_size, sub_tree_total_size): (Vec<Vec<usize>>, Vec<usize>) = spilted_indices
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

#[derive(Clone)]
pub struct DeFRIProver<T: PrimeField> {
    sub_prover_id: usize,
    // should be log_2 m for size-m\ell polynomial
    total_round: usize,
    // number of rounds for distributed computation
    de_round: usize,
    // number of rounds for remaining computation
    // remain_round: usize,
    // sub-polynomial of sub-prover
    // sub_polynomial: UnivariatePolynomial<T>,
    // cosets of the last log_2(n) rounds, only used by master
    interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    // intial interpolations
    initial_interpolations: InterpolateVecsValue<T>,
    // fft evaluations of each round, but only the first is computed from fft
    de_interpolations: Vec<ComOpenOneVec<T>>,
    // sub tree roots
    sub_tree_roots: Vec<[u8; 32]>,
    // merkle tree accumulated by master
    acc_merkle_trees: Vec<MerkleTree<Blake3Algorithm>>,
    // challengs, only master holds
    oracle: Option<RandomOracle<T>>,
    final_value: Option<T>,
}

impl<T: PrimeField> DeFRIProver<T> {
    pub fn new(
        sub_prover_id: usize,
        variable_num: usize,
        interpolate_coset: &Vec<GeneralEvaluationDomain<T>>,
        sub_polynomial: UnivariatePolynomial<T>,
        oracle: Option<&RandomOracle<T>>,
    ) -> DeFRIProver<T> {
        let n = Net::n_parties();
        // interpolate sub-polynomial
        // println!("coset[0] size {:?}", interpolate_coset[0].size());
        // println!("poly size {:?}", sub_polynomial.coeffs.len());
        println!("Prover {:?} starts fft", sub_prover_id);
        let time = Instant::now();
        // let step = start_timer!(|| {
        //     println!("Prover {:?}", sub_prover_id);
        //     "fft"
        // });
        let de_interpolations = interpolate_coset[0].fft(&sub_polynomial.coeffs);
        // end_timer!(step);
        println!("Time: Prover {:?} fft: {:?}", sub_prover_id, time.elapsed());

        // exchange intial interpolations
        let step = start_timer!(|| "exchange interpolations after encoding");
        // let time = Instant::now();
        let first = Net::distribute(&de_interpolations[..de_interpolations.len() / 2], n);
        let second = Net::distribute(&de_interpolations[de_interpolations.len() / 2..], n);
        // println!(
        //     "Time: exchange interpolations after encoding: {:?}",
        //     time.elapsed()
        // );
        end_timer!(step);

        // build initial interpolation vector
        let n = Net::n_parties();
        let size = de_interpolations.len() / (2 * n);
        let step = start_timer!(|| "build leaves");
        // let time = Instant::now();
        let leaves: Vec<Vec<T>> = (0..n)
            .map(|i| {
                let mut combined_segment = Vec::with_capacity(size * 2);
                combined_segment.extend_from_slice(&first[i]);
                combined_segment.extend_from_slice(&second[i]);
                combined_segment
            })
            .collect();
        // println!("Time: build trees: {:?}", time.elapsed());
        end_timer!(step);
        // let time = Instant::now();
        let step = start_timer!(|| "build Merkle tree");
        let initial_interpolations = InterpolateVecsValue::new(leaves);
        end_timer!(step);
        // println!("Time: build Merkle tree: {:?}", time.elapsed());
        println!(
            "initial_interpolations: {} x {}",
            initial_interpolations.values.len(),
            initial_interpolations.values[0].len()
        );

        // total_round = variable_num!!!
        let log_2n = (usize::BITS - Net::n_parties().leading_zeros()) as usize;
        let de_round = variable_num + CODE_RATE - std::cmp::max(log_2n, CODE_RATE);
        let remain_round = variable_num - de_round;

        if Net::am_master() {
            println!(
                "# total rounds: {}, # distributed rounds: {}, # remain rounds: {}",
                variable_num, de_round, remain_round
            );
        }

        DeFRIProver {
            sub_prover_id,
            total_round: de_round + remain_round,
            de_round,
            // remain_round,
            // sub_polynomial,
            interpolate_cosets: interpolate_coset.clone(),
            initial_interpolations,
            de_interpolations: vec![],
            sub_tree_roots: vec![],
            acc_merkle_trees: vec![],
            oracle: oracle.map(|o| o.clone()),
            final_value: None,
        }
    }

    pub fn de_commit_polynomial(
        &mut self,
    ) -> (Option<[u8; MERKLE_ROOT_SIZE]>, Option<Vec<[u8; 32]>>) {
        let sub_com = self.initial_interpolations.commit();
        let step = start_timer!(|| "send sub-tree root");
        // let time = Instant::now();
        let sub_com_vec = Net::send_to_master(&sub_com);
        self.sub_tree_roots.push(sub_com);
        // println!("Time: send sub-tree roots: {:?}", time.elapsed());
        end_timer!(step);
        if Net::am_master() {
            let time = Instant::now();
            self.acc_merkle_trees
                .push(MerkleTree::<Blake3Algorithm>::from_leaves(
                    &sub_com_vec.as_ref().unwrap(),
                ));
            println!("Time: generate Merkle tree root: {:?}", time.elapsed());
            (self.acc_merkle_trees[0].root(), sub_com_vec)
        } else {
            (None, None)
        }
    }

    pub fn de_commit_foldings(
        &mut self,
        verifier: Option<&mut BatchFRIVerifier<T>>,
    ) -> Vec<Vec<[u8; 32]>> {
        let mut de_sub_com_vec = Vec::new();

        if Net::am_master() {
            let verifier = verifier.unwrap();
            verifier.set_final_value(self.final_value.unwrap());

            for i in 1..self.de_round {
                let leaves = &self.de_interpolations[i - 1];
                let sub_com = leaves.commit();
                let sub_com_vec = Net::send_to_master(&sub_com).unwrap();
                self.sub_tree_roots.push(sub_com);

                self.acc_merkle_trees
                    .push(MerkleTree::<Blake3Algorithm>::from_leaves(&sub_com_vec));
                verifier.receive_interpolation_root(
                    Net::n_parties() * leaves.leave_num(),
                    self.acc_merkle_trees[i].root().unwrap(),
                );
                de_sub_com_vec.push(sub_com_vec);
            }

            for i in self.de_round..self.total_round {
                let interpolation = &self.de_interpolations[i - 1];
                verifier
                    .receive_interpolation_root(interpolation.leave_num(), interpolation.commit());
            }

            // verifier.set_final_value(self.final_value.unwrap());
        } else {
            for i in 1..self.de_round {
                let leaves = &self.de_interpolations[i - 1];
                let sub_com = leaves.commit();
                Net::send_to_master(&sub_com);
                self.sub_tree_roots.push(sub_com);
            }
        }
        de_sub_com_vec
    }

    fn evaluation_next_domain(&self, folding_value: &Vec<T>, round: usize, challenge: T) -> Vec<T> {
        let mut res = vec![];
        let len = self.interpolate_cosets[round].size();
        let coset = &self.interpolate_cosets[round];
        for i in 0..(len / 2) {
            let x = folding_value[i];
            let nx = folding_value[i + len / 2];
            let new_v = (x + nx) + challenge * (x - nx) * coset.element(i).inverse().unwrap();
            let new_v = new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap();
            res.push(new_v);
        }
        res
    }

    fn de_evaluation_next_domain(
        &self,
        folding_value_first: &Vec<T>,
        folding_value_second: &Vec<T>,
        round: usize,
        challenge: T,
    ) -> Vec<T> {
        let mut res = vec![];
        let n = Net::n_parties();
        let id = self.sub_prover_id;
        let half_domain_size = self.interpolate_cosets[round].size() / 4;
        let len = self.interpolate_cosets[round].size() / n;
        let offset = id * (len / 4);

        let coset = &self.interpolate_cosets[round];

        for i in 0..(len / 4) {
            let x = folding_value_first[i];
            let nx = folding_value_second[i];
            let new_v =
                (x + nx) + challenge * (x - nx) * coset.element(i + offset).inverse().unwrap();
            let new_v = new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap();
            res.push(new_v);
        }

        for i in 0..(len / 4) {
            let x = folding_value_first[i + len / 4];
            let nx = folding_value_second[i + len / 4];
            let new_v = (x + nx)
                + challenge
                    * (x - nx)
                    * coset
                        .element(i + offset + half_domain_size)
                        .inverse()
                        .unwrap();
            let new_v = new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap();
            res.push(new_v);
        }

        res
    }

    pub fn de_prove(&mut self) {
        let n = Net::n_parties();
        for i in 0..self.total_round {
            // distribute proving
            if i < self.de_round {
                // master sends folding_challenge to de_provers
                let folding_challenge = if Net::am_master() {
                    Net::recv_from_master(Some(vec![
                        self.oracle
                            .as_ref()
                            .unwrap()
                            .folding_challenges[i];
                        n
                    ]))
                } else {
                    Net::recv_from_master(None)
                };
                // fold the polynomial
                let next_evaluation = if i == 0 {
                    let vecs = self.initial_interpolations.values.clone();
                    // master sends rlc_challenge to de_provers
                    let rlc = if Net::am_master() {
                        Net::recv_from_master(Some(vec![self.oracle.as_ref().unwrap().rlc; n]))
                    } else {
                        Net::recv_from_master(None)
                    };
                    // println!("rlc challenge is: {}", rlc);

                    let mut rlc_challenge = rlc;
                    let mut final_vec = vecs[0].clone();

                    // rlc evaluations
                    for j in 1..Net::n_parties() {
                        for (k, x) in vecs[j].iter().enumerate() {
                            final_vec[k] += *x * rlc_challenge;
                        }
                        rlc_challenge *= rlc;
                    }

                    // exchange rlc results
                    let interpolations_len = final_vec.len();
                    let first = Net::exchange(&final_vec[..interpolations_len / 2]);
                    let second = Net::exchange(&final_vec[interpolations_len / 2..]);

                    // fold the exchanged polynomial
                    self.de_evaluation_next_domain(&first, &second, i, folding_challenge)
                } else {
                    // exchange the folded polynomial
                    let interpolations_len = self.de_interpolations[i - 1].vec.len();
                    let first =
                        Net::exchange(&self.de_interpolations[i - 1].vec[..interpolations_len / 2]);
                    let second =
                        Net::exchange(&self.de_interpolations[i - 1].vec[interpolations_len / 2..]);

                    // fold the exchanged polynomial
                    self.de_evaluation_next_domain(&first, &second, i, folding_challenge)
                };

                // send all evaluations to the master in the last de_round
                if i == self.de_round - 1 {
                    // println!("size after final de_round: {}", next_evalutation.len());
                    let interpolations = Net::send_to_master(&next_evaluation);
                    if Net::am_master() {
                        let interpolations = interpolations.unwrap();
                        let result: Vec<T> = interpolations
                            .iter()
                            .map(|x| x[0].clone())
                            .chain(interpolations.iter().map(|x| x[1].clone()))
                            .collect();

                        self.de_interpolations.push(ComOpenOneVec::new(result));
                    }
                }

                if i < self.total_round - 1 && i != self.de_round - 1 {
                    self.de_interpolations
                        .push(ComOpenOneVec::new(next_evaluation));
                } else if i == self.total_round - 1 {
                    if Net::am_master() {
                        self.final_value = Some(next_evaluation[0]);
                    }
                }

                // println!("id: {}, de_round: {}", self.sub_prover_id, i);
            } else {
                if Net::am_master() {
                    let next_evaluation = self.evaluation_next_domain(
                        &self.de_interpolations[i - 1].vec,
                        i,
                        self.oracle.as_ref().unwrap().folding_challenges[i],
                    );

                    if i < self.total_round - 1 {
                        self.de_interpolations
                            .push(ComOpenOneVec::new(next_evaluation));
                    } else {
                        self.final_value = Some(next_evaluation[0]);
                    }
                    // println!("id: {}, remain_round: {}", self.sub_prover_id, i);
                }
            }
        }
    }

    pub fn de_open(
        &mut self,
        intial_sub_tree_roots: Option<Vec<[u8; 32]>>,
        verifier: Option<&mut BatchFRIVerifier<T>>,
    ) -> (QueryVecsResult<T>, Vec<QueryResult<T>>) {
        let n = Net::n_parties();

        self.de_prove();

        let de_sub_roots_vec = self.de_commit_foldings(verifier);

        let mut folding_initial_res: QueryVecsResult<T> = QueryVecsResult::new();
        let mut folding_res: Vec<QueryResult<T>> = vec![];

        // master distributes the query list
        let mut leaf_indices: Vec<usize> = if Net::am_master() {
            let query_list: Vec<Vec<usize>> = (0..n)
                .map(|_| self.oracle.as_ref().unwrap().query_list.clone())
                .collect();
            assert_eq!(query_list[0].len(), SECURITY_BITS / CODE_RATE);
            Net::recv_from_master::<Vec<usize>>(Some(query_list))
        } else {
            Net::recv_from_master::<Vec<usize>>(None)
        };
        // println!("id: {}, leaf_indices: {:?}", Net::party_id(), leaf_indices);

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[0].size() / (1 << i);
            // println!("round: {}, len of challenge: {}", i, len);
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            let id = self.sub_prover_id;
            let mut indices: Vec<usize> = Vec::new();
            if i < self.de_round {
                let start = id * (len >> 1) / n;
                let end = start + (len >> 1) / n;
                // println!("round: {}, id: {}, from {} to {}", i, id, start, end - 1);
                indices = indices_spilt(&leaf_indices, start, end);
                indices = indices
                    .iter()
                    .map(|index| index - ((len >> 1) / n) * id)
                    .collect();
            } else {
                if Net::am_master() {
                    indices = leaf_indices.clone();
                    // println!("round: {}, id: {}, size: {}", i, id, indices.len());
                }
            }
            // println!("round: {}, id: {}, query_num: {}", i, id, indices.len());

            if i == 0 {
                // open query results
                let query_res = if indices.len() == 0 {
                    QueryVecsResult::new()
                } else {
                    self.initial_interpolations.query(&indices)
                };
                // sends query results to master
                let received_qurey_res =
                    Net::send_to_master(&QueryVecsResultTest::from_query_vecs_result(&query_res));
                // master combines query results
                if Net::am_master() {
                    // println!("round: {}", i);
                    let tmp: Vec<QueryVecsResult<T>> = received_qurey_res
                        .unwrap()
                        .into_iter()
                        .map(|qurey_res| qurey_res.to_query_vecs_result())
                        .collect();
                    folding_initial_res = combine_query_vecs_results(
                        &tmp,
                        &intial_sub_tree_roots.as_ref().unwrap(),
                        &leaf_indices,
                        (len >> 1) / n,
                    );
                    // verifies combined query results
                    debug_assert!(verify_query_vecs_results(
                        &folding_initial_res,
                        &self.acc_merkle_trees[0].root().unwrap(),
                        &leaf_indices,
                        len >> 1,
                    ));
                }
            } else if i < self.de_round {
                // open query results
                let query_res = if indices.len() == 0 {
                    QueryResult::new()
                } else {
                    self.de_interpolations[i - 1].open(&indices)
                };

                if indices.len() == 0 {
                    assert_eq!(query_res.proof_values.len(), 0);
                    assert_eq!(query_res.proof_bytes.len(), 0);
                } else {
                    debug_assert!(verify_query_results(
                        &query_res,
                        &self.sub_tree_roots[i],
                        &indices,
                        (len >> 1) / n,
                    ));
                }
                // sends query results to master
                let received_qurey_res =
                    Net::send_to_master(&QueryResultTest::from_query_result(&query_res));
                // master combines query results
                if Net::am_master() {
                    // println!("round: {}", i);
                    let tmp: Vec<QueryResult<T>> = received_qurey_res
                        .unwrap()
                        .into_iter()
                        .map(|qurey_res| qurey_res.to_query_result())
                        .collect();
                    folding_res.push(combine_query_results(
                        &tmp,
                        &de_sub_roots_vec[i - 1],
                        &leaf_indices,
                        (len >> 1) / n,
                    ));
                    // verifies combined query results
                    debug_assert!(verify_query_results(
                        &folding_res[i - 1],
                        &self.acc_merkle_trees[i].root().unwrap(),
                        &leaf_indices,
                        len >> 1,
                    ));
                }
            } else {
                if Net::am_master() {
                    folding_res.push(self.de_interpolations[i - 1].open(&indices));
                }
            }
        }

        (folding_initial_res, folding_res)
    }
}
