use std::time::Instant;

use super::verifier::Verifier;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer};
use de_network::{DeMultiNet as Net, DeNet, DeSerNet};
use rs_merkle::MerkleTree;
use utils::commit_open_vec::ComOpenOneVec;
use utils::helper::indices_spilt;
use utils::helper::Helper;
use utils::helper::MultilinearPolynomial;
use utils::interpolate_vecs_value::QueryVecsResultTest;
use utils::interpolate_vecs_value::{InterpolateVecsValue, QueryVecsResult};
use utils::merkle_tree::Blake3Algorithm;
pub use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::query_result::QueryResult;
use utils::query_result::QueryResultTest;
use utils::time_logger::LOGGER;
use utils::{fiat_shamir::RandomOracle, CODE_RATE};

#[derive(Clone)]
pub struct DeProver<T: PrimeField> {
    // round number for sub_polynomials
    pub total_round: usize,
    pub de_round: usize,
    pub sub_prover_id: usize,
    pub interpolate_cosets: Vec<GeneralEvaluationDomain<T>>,
    pub interpolate_initial_polynomials: InterpolateVecsValue<T>,
    interpolate_rlc_polynomial: Vec<T>,
    interpolate_tensor_polynomial: Vec<T>,
    functions: Vec<ComOpenOneVec<T>>,
    functions_first: Vec<Vec<T>>,
    functions_second: Vec<Vec<T>>,
    foldings: Vec<ComOpenOneVec<T>>,
    sub_intial_tree_root: [u8; MERKLE_ROOT_SIZE],
    sub_func_tree_roots: Vec<[u8; MERKLE_ROOT_SIZE]>,
    sub_fold_tree_roots: Vec<[u8; MERKLE_ROOT_SIZE]>,
    acc_intial_tree: MerkleTree<Blake3Algorithm>,
    acc_func_trees: Vec<MerkleTree<Blake3Algorithm>>,
    acc_fold_trees: Vec<MerkleTree<Blake3Algorithm>>,
    pub oracle: Option<RandomOracle<T>>,
    final_value: Option<T>,
}

impl<T: PrimeField> DeProver<T> {
    pub fn new(
        total_round: usize,
        sub_prover_id: usize,
        interpolate_cosets: &Vec<GeneralEvaluationDomain<T>>,
        sub_polys: Vec<MultilinearPolynomial<T>>,
        // oracle has a random_linear_combination challenge
        oracle: Option<&RandomOracle<T>>,
        // the fixed combination to combine multiple sub polynomials
        tensor: &Vec<T>,
    ) -> DeProver<T> {
        let total_t = Instant::now();
        // let t1 = Instant::now();
        let n = Net::n_parties();

        let step = start_timer!(|| "NTT");

        let de_interpolations_vec: Vec<Vec<T>> = (0..sub_polys.len())
            .map(|i| interpolate_cosets[0].fft(&sub_polys[i].coefficients()))
            .collect();

        end_timer!(step);
        // LOGGER.lock().unwrap().record(t1.elapsed().as_secs_f64());

        // exchange intial interpolations
        let step = start_timer!(|| "Exchange inital interpolations");
        let time = Instant::now();
        let distributed_interpolations: Vec<(Vec<_>, Vec<_>)> = (0..sub_polys.len())
            .map(|i| {
                let de_interpolations = &de_interpolations_vec[i];
                (
                    Net::distribute(&de_interpolations[..de_interpolations.len() / 2], n),
                    Net::distribute(&de_interpolations[de_interpolations.len() / 2..], n),
                )
            })
            .collect();

        let (first, second): (Vec<&[T]>, Vec<&[T]>) = (0..n)
            .flat_map(|i| {
                distributed_interpolations
                    .iter()
                    .map(move |(first_half, second_half)| (&first_half[i][..], &second_half[i][..]))
            })
            .unzip();
        assert_eq!(first.len(), n * sub_polys.len());

        let size = interpolate_cosets[0].size() / (2 * n);
        assert_eq!(first[0].len(), size);

        let leaves: Vec<Vec<T>> = (0..n * sub_polys.len())
            .map(|i| {
                let mut combined_segment = Vec::with_capacity(size * 2);
                combined_segment.extend_from_slice(&first[i]);
                combined_segment.extend_from_slice(&second[i]);
                combined_segment
            })
            .collect();
        end_timer!(step);
        let exchange_time = time.elapsed().as_secs_f64();
        // println!("Exchange inital interpolations time: {:?}", time.elapsed());

        // Compute the actual polynomial invoked into FRI
        let step = start_timer!(|| "rlc");

        // master sends rlc_challenge to de_provers
        let rlc = if Net::am_master() {
            Net::recv_from_master(Some(vec![oracle.as_ref().unwrap().rlc; n]))
        } else {
            Net::recv_from_master(None)
        };

        let mut rlc_polynomial = leaves[0].clone();
        assert_eq!(rlc_polynomial.len(), 2 * size);

        for i in leaves.iter().skip(1) {
            for j in 0..rlc_polynomial.len() {
                rlc_polynomial[j] *= rlc;
                rlc_polynomial[j] += i[j];
            }
        }
        // Compute the tensor_polynomial, the actual polynomial invoked into function
        let tensor_polynomial = Helper::linear_combine(tensor, &leaves);
        end_timer!(step);

        // this step takes the majority of time
        let step = start_timer!(|| "Merkle tree");

        let initial_interpolations = InterpolateVecsValue::new(leaves);
        end_timer!(step);

        // total_round = variable_num!!!
        let log_2n = (usize::BITS - n.leading_zeros()) as usize;
        let de_round = total_round + CODE_RATE - std::cmp::max(log_2n, CODE_RATE);
        let remain_round = total_round - de_round;

        LOGGER
            .lock()
            .unwrap()
            .record(total_t.elapsed().as_secs_f64() - exchange_time);

        if Net::am_master() {
            println!(
                "# total rounds: {}, # distributed rounds: {}, # remain rounds: {}",
                total_round, de_round, remain_round
            );
        }

        DeProver {
            total_round,
            de_round,
            sub_prover_id,
            interpolate_cosets: interpolate_cosets.clone(),
            interpolate_initial_polynomials: initial_interpolations,
            // interpolate_polynomials,
            interpolate_rlc_polynomial: rlc_polynomial,
            interpolate_tensor_polynomial: tensor_polynomial,
            functions: vec![],
            functions_first: vec![],
            functions_second: vec![],
            foldings: vec![],
            sub_intial_tree_root: [0; 32],
            sub_func_tree_roots: vec![],
            sub_fold_tree_roots: vec![],
            acc_intial_tree: MerkleTree::<Blake3Algorithm>::new(),
            acc_func_trees: vec![],
            acc_fold_trees: vec![],
            oracle: oracle.map(|o| o.clone()),
            final_value: None,
        }
    }

    pub fn de_commit_polynomial(
        &mut self,
    ) -> (Option<[u8; MERKLE_ROOT_SIZE]>, Option<Vec<[u8; 32]>>) {
        let step = start_timer!(|| "Merkle tree");
        let sub_com = self.interpolate_initial_polynomials.commit();
        end_timer!(step);
        let step = start_timer!(|| "send sub-root");
        let intial_sub_com = Net::send_to_master(&sub_com);
        self.sub_intial_tree_root = sub_com;
        end_timer!(step);
        if Net::am_master() {
            self.acc_intial_tree =
                MerkleTree::<Blake3Algorithm>::from_leaves(&intial_sub_com.as_ref().unwrap());
            (self.acc_intial_tree.root(), intial_sub_com)
        } else {
            (None, None)
        }
    }

    // used for function recursive
    fn fold(values: &Vec<T>, parameter: T, coset: &GeneralEvaluationDomain<T>) -> Vec<T> {
        let len = values.len() / 2;
        let res = (0..len)
            .into_iter()
            .map(|i| {
                let x = values[i];
                let nx = values[i + len];
                let new_v = (x + nx) + parameter * (x - nx) * coset.element(i).inverse().unwrap();
                new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap()
            })
            .collect();
        res
    }

    // used for function recursive
    fn de_fold(
        folding_values_first: &Vec<T>,
        folding_values_second: &Vec<T>,
        parameter: T,
        coset: &GeneralEvaluationDomain<T>,
    ) -> Vec<T> {
        let mut res = vec![];
        let n = Net::n_parties();
        let id = Net::party_id();
        let half_domain_size = coset.size() / 4;
        let len = coset.size() / n;
        let offset = id * (len / 4);

        for i in 0..(len / 4) {
            let x = folding_values_first[i];
            let nx = folding_values_second[i];
            let new_v =
                (x + nx) + parameter * (x - nx) * coset.element(i + offset).inverse().unwrap();
            let new_v = new_v * T::from_u64(2 as u64).unwrap().inverse().unwrap();
            res.push(new_v);
        }

        for i in 0..(len / 4) {
            let x = folding_values_first[i + len / 4];
            let nx = folding_values_second[i + len / 4];
            let new_v = (x + nx)
                + parameter
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

    // generate f_1, f_2, ..., f_{\mu - 1}, and f_\mu
    // function[0], function[1], ..., function[\mu - 2]
    // function[0] is f_1, and f_\mu is a constant
    // f_0 is a virtual polynomial as tensor_polynomial
    pub fn de_commit_functions(
        &mut self,
        sub_open_point: &Vec<T>,
        verifier: Option<&mut Verifier<T>>,
    ) -> Vec<Vec<[u8; 32]>> {
        let n = Net::n_parties();
        let mut evaluation = None;
        let mut func_sub_com_vec = Vec::new();

        let mut exchange_time: f64 = 0.0;
        for round in 0..self.total_round {
            if round < self.de_round {
                let next_evaluation;
                if round == 0 {
                    // exchange the tensor poly
                    let interpolations_len = self.interpolate_tensor_polynomial.len();
                    let time = Instant::now();
                    let first = Net::exchange(
                        &self.interpolate_tensor_polynomial[..interpolations_len / 2],
                    );
                    let second = Net::exchange(
                        &self.interpolate_tensor_polynomial[interpolations_len / 2..],
                    );
                    exchange_time += time.elapsed().as_secs_f64();

                    // fold the exchanged poly
                    next_evaluation = Self::de_fold(
                        &first,
                        &second,
                        sub_open_point[round],
                        &self.interpolate_cosets[round],
                    )
                } else {
                    // exchange the folded poly
                    let interpolations_len = self.functions[round - 1].vec.len();
                    let time = Instant::now();
                    let first =
                        Net::exchange(&self.functions[round - 1].vec[..interpolations_len / 2]);
                    let second =
                        Net::exchange(&self.functions[round - 1].vec[interpolations_len / 2..]);
                    exchange_time += time.elapsed().as_secs_f64();
                    // fold the exchanged poly

                    next_evaluation = Self::de_fold(
                        &first,
                        &second,
                        sub_open_point[round],
                        &self.interpolate_cosets[round],
                    );

                    self.functions_first.push(first);
                    self.functions_second.push(second);
                };

                if round == self.de_round - 1 {
                    // send interpolations to master in the last de_round
                    let interpolations = Net::send_to_master(&next_evaluation);
                    if Net::am_master() {
                        let interpolations = interpolations.unwrap();
                        let result: Vec<T> = interpolations
                            .iter()
                            .map(|x| x[0].clone())
                            .chain(interpolations.iter().map(|x| x[1].clone()))
                            .collect();

                        self.functions.push(ComOpenOneVec::new(result));
                    }
                }

                if round < self.total_round - 1 && round != self.de_round - 1 {
                    self.functions.push(ComOpenOneVec::new(next_evaluation));
                } else if round == self.total_round - 1 {
                    if Net::am_master() {
                        assert_eq!(n * next_evaluation.len(), 1 << CODE_RATE);
                        evaluation = Some(next_evaluation[0]);
                    }
                }

                // println!("id: {}, de_round: {}", self.sub_prover_id, round);
            } else {
                if Net::am_master() {
                    let next_evaluation = Self::fold(
                        &self.functions[round - 1].vec,
                        sub_open_point[round],
                        &self.interpolate_cosets[round],
                    );

                    if round < self.total_round - 1 {
                        self.functions.push(ComOpenOneVec::new(next_evaluation));
                    } else {
                        assert_eq!(next_evaluation.len(), 1 << CODE_RATE);
                        evaluation = Some(next_evaluation[0]);
                    }

                    // println!("id: {}, remain_round: {}", self.sub_prover_id, round);
                }
            }
        }

        if Net::am_master() {
            let verifier = verifier.unwrap();
            verifier.set_evaluation(evaluation.unwrap());

            for round in 1..self.de_round {
                let function = &self.functions[round - 1];
                let sub_com = function.commit();
                let sub_com_vec = Net::send_to_master(&sub_com).unwrap();
                self.sub_func_tree_roots.push(sub_com);

                self.acc_func_trees
                    .push(MerkleTree::<Blake3Algorithm>::from_leaves(&sub_com_vec));

                verifier.set_function(
                    n * function.leave_num(),
                    &self.acc_func_trees[round - 1].root().unwrap(),
                );
                func_sub_com_vec.push(sub_com_vec);
            }

            for round in self.de_round..self.total_round {
                let function = &self.functions[round - 1];
                verifier.set_function(function.leave_num(), &function.commit());
            }
        } else {
            for round in 1..self.de_round {
                let leaves = &self.functions[round - 1];
                let sub_com = leaves.commit();
                Net::send_to_master(&sub_com);
                self.sub_func_tree_roots.push(sub_com);
            }
        }
        LOGGER.lock().unwrap().record(exchange_time);

        func_sub_com_vec
    }

    pub fn de_commit_foldings(&mut self, verifier: Option<&mut Verifier<T>>) -> Vec<Vec<[u8; 32]>> {
        let n = Net::n_parties();
        let mut fold_sub_com_vec = Vec::new();

        if Net::am_master() {
            let verifier = verifier.unwrap();
            verifier.set_final_value(self.final_value.unwrap());

            for round in 1..self.de_round {
                let folding = &self.foldings[round - 1];
                let sub_com = folding.commit();
                let sub_com_vec = Net::send_to_master(&sub_com).unwrap();
                self.sub_fold_tree_roots.push(sub_com);

                self.acc_fold_trees
                    .push(MerkleTree::<Blake3Algorithm>::from_leaves(&sub_com_vec));

                verifier.receive_folding_root(
                    n * folding.leave_num(),
                    self.acc_fold_trees[round - 1].root().unwrap(),
                );
                fold_sub_com_vec.push(sub_com_vec);
            }

            for round in self.de_round..self.total_round {
                let folding = &self.foldings[round - 1];
                verifier.receive_folding_root(folding.leave_num(), folding.commit());
            }
        } else {
            for round in 1..self.de_round {
                let leaves = &self.foldings[round - 1];
                let sub_com = leaves.commit();
                Net::send_to_master(&sub_com);
                self.sub_fold_tree_roots.push(sub_com);
            }
        }

        fold_sub_com_vec
    }

    // generate and push foldings, p_0, p_1, ..., p_{\mu - 1}, where p_{\mu - 1} is a constant
    // p_0 = g_0(X) + \alpha_0 h_0(X), and f_0(X) = g_0(X^2) + X h_0(X^2)
    // \phi_1(X) = p_0 + \alpha_0^2 f_1,
    // p_1 = g_1 + alpha_1 h_1, and \phi_1(X) = g_1(X^2) + X h_1(X^2)
    // ....
    // folding[0] is p_0,
    fn evaluation_next_domain(
        &self,
        round: usize,
        last_challenge: Option<T>,
        cur_challenge: T,
    ) -> Vec<T> {
        let mut res = vec![];
        let len = self.interpolate_cosets[round].size();
        let get_folding_value = if round == 0 {
            &self.interpolate_rlc_polynomial
        } else {
            &self.foldings[round - 1].vec
        };
        let coset = &self.interpolate_cosets[round];
        for i in 0..(len / 2) {
            if round == 0 {
                assert_eq!(last_challenge, None);
                let x = get_folding_value[i];
                let nx = get_folding_value[i + len / 2];
                let new_v =
                    (x + nx) + cur_challenge * (x - nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            } else {
                let fv = &self.functions[round - 1].vec;
                assert_eq!(fv.len(), get_folding_value.len());
                let x = fv[i];
                let nx = fv[i + len / 2];
                let last_challenge_square = last_challenge.unwrap().pow([2 as u64]);
                let phi_x = get_folding_value[i] + last_challenge_square * x;
                let phi_nx = get_folding_value[i + len / 2] + last_challenge_square * nx;
                let new_v = (phi_x + phi_nx)
                    + cur_challenge * (phi_x - phi_nx) * coset.element(i).inverse().unwrap();
                res.push(new_v);
            }
        }
        res
    }

    // \hat{f}^(1), ... , \hat{f}^(l) => f^(0)(X)
    // f_0, f_1, ... , f_\mu are folded functions
    // generate and push foldings, p_0, p_1, ..., p_{\mu - 1}, where p_{\mu - 1} is a constant
    // p_0 = g_0(X) + \alpha_0 h_0(X), and f^(0)(X) = g'_0(X^2) + X h'_0(X^2)
    // \phi_1(X) = p_0 + \alpha_0^2 f_1,
    // p_1 = g_1(X) + \alpha_1 h_1(X), and f^(1)(X) = g'_1(X^2) + X h'_1(X^2)
    // \phi_2(X) = p_1 + \alpha_1^2 f_2,
    // ...
    // folding[0] is p_0,
    fn de_evaluation_next_domain(
        &self,
        folding_values_first: &Vec<T>,
        folding_values_second: &Vec<T>,
        round: usize,
        last_challenge: Option<T>,
        cur_challenge: T,
    ) -> Vec<T> {
        let mut res = vec![];

        let coset = &self.interpolate_cosets[round];
        let half_domain_size = self.interpolate_cosets[round].size() / 4;
        let len = self.interpolate_cosets[round].size() / Net::n_parties();
        let offset = self.sub_prover_id * (len / 4);

        let mut fv_first = &Vec::new();
        let mut fv_second = &Vec::new();
        if round != 0 {
            fv_first = &self.functions_first[round - 1];
            assert_eq!(fv_first.len(), folding_values_first.len());
            fv_second = &self.functions_second[round - 1];
            assert_eq!(fv_second.len(), folding_values_second.len());
        }

        for i in 0..(len / 4) {
            if round == 0 {
                assert_eq!(last_challenge, None);
                // g_0(X)
                let x = folding_values_first[i];
                // h_0(X)
                let nx = folding_values_second[i];
                // p_0(X)
                let new_v = (x + nx)
                    + cur_challenge * (x - nx) * coset.element(i + offset).inverse().unwrap();
                res.push(new_v);
            } else {
                let last_challenge_square = last_challenge.unwrap().pow([2 as u64]);
                // \phi_{round}(X) = p_{round-1} + \alpha_{round-1}^2 f_{round},
                let phi_x = folding_values_first[i] + last_challenge_square * fv_first[i];
                let phi_nx = folding_values_second[i] + last_challenge_square * fv_second[i];
                let new_v = (phi_x + phi_nx)
                    + cur_challenge
                        * (phi_x - phi_nx)
                        * coset.element(i + offset).inverse().unwrap();
                res.push(new_v);
            }
        }

        for i in 0..(len / 4) {
            if round == 0 {
                let x = folding_values_first[i + len / 4];
                let nx = folding_values_second[i + len / 4];
                let new_v = (x + nx)
                    + cur_challenge
                        * (x - nx)
                        * coset
                            .element(i + offset + half_domain_size)
                            .inverse()
                            .unwrap();
                res.push(new_v);
            } else {
                let last_challenge_square = last_challenge.unwrap().pow([2 as u64]);
                let phi_x = folding_values_first[i + len / 4]
                    + last_challenge_square * fv_first[i + len / 4];
                let phi_nx = folding_values_second[i + len / 4]
                    + last_challenge_square * fv_second[i + len / 4];
                let new_v = (phi_x + phi_nx)
                    + cur_challenge
                        * (phi_x - phi_nx)
                        * coset
                            .element(i + offset + half_domain_size)
                            .inverse()
                            .unwrap();
                res.push(new_v);
            }
        }

        res
    }

    // commit foldings
    pub fn de_prove(&mut self) {
        let n = Net::n_parties();
        let mut folding_challenges = Vec::new();
        let mut exchange_time: f64 = 0.0;

        // master distributes challenges for folding
        for round in 0..self.de_round {
            let cur_challenge = if Net::am_master() {
                Net::recv_from_master(Some(vec![
                    self.oracle.as_ref().unwrap().folding_challenges
                        [round];
                    n
                ]))
            } else {
                Net::recv_from_master(None)
            };
            folding_challenges.push(cur_challenge);
        }

        for round in 0..self.total_round {
            if round < self.de_round {
                let cur_challenge = folding_challenges[round];

                let last_challenge = if round > 0 {
                    Some(folding_challenges[round - 1])
                } else {
                    None
                };

                let next_evaluation = if round == 0 {
                    // exchange the tensor poly
                    let interpolations_len = self.interpolate_rlc_polynomial.len();
                    let time = Instant::now();
                    let first =
                        Net::exchange(&self.interpolate_rlc_polynomial[..interpolations_len / 2]);
                    let second =
                        Net::exchange(&self.interpolate_rlc_polynomial[interpolations_len / 2..]);
                    exchange_time += time.elapsed().as_secs_f64();

                    // fold the exchanged poly
                    self.de_evaluation_next_domain(
                        &first,
                        &second,
                        round,
                        last_challenge,
                        cur_challenge,
                    )
                } else {
                    // exchange the folded poly
                    let interpolations_len = self.foldings[round - 1].vec.len();
                    let time = Instant::now();
                    let first =
                        Net::exchange(&self.foldings[round - 1].vec[..interpolations_len / 2]);
                    let second =
                        Net::exchange(&self.foldings[round - 1].vec[interpolations_len / 2..]);
                    exchange_time += time.elapsed().as_secs_f64();

                    // fold the exchanged poly
                    self.de_evaluation_next_domain(
                        &first,
                        &second,
                        round,
                        last_challenge,
                        cur_challenge,
                    )
                };

                if round == self.de_round - 1 {
                    // send interpolations to master in the last de_round
                    let interpolations = Net::send_to_master(&next_evaluation);
                    if Net::am_master() {
                        let interpolations = interpolations.unwrap();
                        let result: Vec<T> = interpolations
                            .iter()
                            .map(|x| x[0].clone())
                            .chain(interpolations.iter().map(|x| x[1].clone()))
                            .collect();

                        self.foldings.push(ComOpenOneVec::new(result));
                    }
                }

                if round < self.total_round - 1 && round != self.de_round - 1 {
                    self.foldings.push(ComOpenOneVec::new(next_evaluation));
                } else if round == self.total_round - 1 {
                    if Net::am_master() {
                        assert_eq!(n * next_evaluation.len(), 1 << CODE_RATE);
                        self.final_value = Some(next_evaluation[0]);
                    }
                }
            } else {
                if Net::am_master() {
                    let next_evaluation = self.evaluation_next_domain(
                        round,
                        Some(self.oracle.as_ref().unwrap().folding_challenges[round - 1]),
                        self.oracle.as_ref().unwrap().folding_challenges[round],
                    );

                    if round < self.total_round - 1 {
                        self.foldings.push(ComOpenOneVec::new(next_evaluation));
                    } else {
                        assert_eq!(next_evaluation.len(), 1 << CODE_RATE);
                        self.final_value = Some(next_evaluation[0]);
                    }
                }
            }
        }
        LOGGER.lock().unwrap().record(exchange_time);
    }

    pub fn query(&self) -> (QueryVecsResult<T>, Vec<QueryResult<T>>, Vec<QueryResult<T>>) {
        let mut folding_res = vec![];
        let mut functions_res = vec![];
        let mut polynomial_res = None;
        let mut leaf_indices = self.oracle.as_ref().unwrap().query_list.clone();

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                polynomial_res = Some(self.interpolate_initial_polynomials.query(&leaf_indices));
            } else {
                functions_res.push(self.functions[i - 1].open(&leaf_indices));
                folding_res.push(self.foldings[i - 1].open(&leaf_indices));
            }
        }
        (polynomial_res.unwrap(), folding_res, functions_res)
    }

    pub fn de_query(
        &self,
        intial_sub_com: Option<&Vec<[u8; 32]>>,
        func_sub_com_vec: &Vec<Vec<[u8; 32]>>,
        fold_sub_com_vec: &Vec<Vec<[u8; 32]>>,
    ) -> (QueryVecsResult<T>, Vec<QueryResult<T>>, Vec<QueryResult<T>>) {
        let n = Net::n_parties();
        let mut polynomial_res = QueryVecsResult::new();
        let mut functions_res = vec![];
        let mut folding_res = vec![];

        // master distributes the query list
        let mut leaf_indices: Vec<usize> = if Net::am_master() {
            let query_list: Vec<Vec<usize>> = (0..n)
                .map(|_| self.oracle.as_ref().unwrap().query_list.clone())
                .collect();
            assert_eq!(
                query_list[0].len(),
                self.oracle.as_ref().unwrap().query_list.len()
            );
            Net::recv_from_master::<Vec<usize>>(Some(query_list))
        } else {
            Net::recv_from_master::<Vec<usize>>(None)
        };

        for i in 0..self.total_round {
            let len = self.interpolate_cosets[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            // spilt leaf indices
            let id = self.sub_prover_id;
            let mut indices: Vec<usize> = Vec::new();
            if i < self.de_round {
                let start = id * (len >> 1) / n;
                let end = start + (len >> 1) / n;
                indices = indices_spilt(&leaf_indices, start, end);
                indices = indices
                    .iter()
                    .map(|index| index - ((len >> 1) / n) * id)
                    .collect();
            } else {
                if Net::am_master() {
                    indices = leaf_indices.clone();
                }
            }

            if i == 0 {
                // open query results
                let query_res: QueryVecsResult<T> = if indices.len() == 0 {
                    QueryVecsResult::new()
                } else {
                    self.interpolate_initial_polynomials.query(&indices)
                };
                // send query results to the master
                let received_qurey_res =
                    Net::send_to_master(&QueryVecsResultTest::from_query_vecs_result(&query_res));
                if Net::am_master() {
                    // master combines query results
                    let tmp: Vec<QueryVecsResult<T>> = received_qurey_res
                        .unwrap()
                        .into_iter()
                        .map(|qurey_res| qurey_res.to_query_vecs_result())
                        .collect();
                    polynomial_res = Helper::combine_query_vecs_results(
                        &tmp,
                        &intial_sub_com.unwrap(),
                        &leaf_indices,
                        (len >> 1) / n,
                    );
                    // verify combined query results
                    debug_assert!(Helper::verify_query_vecs_results(
                        &polynomial_res,
                        &self.acc_intial_tree.root().unwrap(),
                        &leaf_indices,
                        len >> 1,
                    ));
                }
            } else if i < self.de_round {
                // open query results
                let func_query_res = if indices.len() == 0 {
                    QueryResult::new()
                } else {
                    self.functions[i - 1].open(&indices)
                };
                let fold_query_res = if indices.len() == 0 {
                    QueryResult::new()
                } else {
                    self.foldings[i - 1].open(&indices)
                };
                // sends query results to master
                let received_func_qurey_res =
                    Net::send_to_master(&QueryResultTest::from_query_result(&func_query_res));
                let received_fold_qurey_res =
                    Net::send_to_master(&QueryResultTest::from_query_result(&fold_query_res));
                // master combines query results
                if Net::am_master() {
                    let tmp_0: Vec<QueryResult<T>> = received_func_qurey_res
                        .unwrap()
                        .into_iter()
                        .map(|query_res| query_res.to_query_result())
                        .collect();
                    functions_res.push(Helper::combine_query_results(
                        &tmp_0,
                        &func_sub_com_vec[i - 1],
                        &leaf_indices,
                        (len >> 1) / n,
                    ));
                    // verifies combined query results
                    debug_assert!(Helper::verify_query_results(
                        &functions_res[i - 1],
                        &self.acc_func_trees[i - 1].root().unwrap(),
                        &leaf_indices,
                        len >> 1,
                    ));

                    let tmp_1: Vec<QueryResult<T>> = received_fold_qurey_res
                        .unwrap()
                        .into_iter()
                        .map(|fold_res| fold_res.to_query_result())
                        .collect();
                    folding_res.push(Helper::combine_query_results(
                        &tmp_1,
                        &fold_sub_com_vec[i - 1],
                        &leaf_indices,
                        (len >> 1) / n,
                    ));
                    // verifies combined query results
                    debug_assert!(Helper::verify_query_results(
                        &folding_res[i - 1],
                        &self.acc_fold_trees[i - 1].root().unwrap(),
                        &leaf_indices,
                        len >> 1,
                    ));
                }
            } else {
                if Net::am_master() {
                    functions_res.push(self.functions[i - 1].open(&indices));
                    folding_res.push(self.foldings[i - 1].open(&indices));
                }
            }
        }
        (polynomial_res, folding_res, functions_res)
    }

    pub fn de_open(
        &mut self,
        intial_sub_com: &Option<Vec<[u8; 32]>>,
        sub_open_point: &Vec<T>,
        mut verifier: Option<&mut Verifier<T>>,
    ) -> (QueryVecsResult<T>, Vec<QueryResult<T>>, Vec<QueryResult<T>>) {
        let func_sub_com_vec =
            self.de_commit_functions(&sub_open_point.to_vec(), verifier.as_deref_mut());
        self.de_prove();
        let fold_sub_com_vec = self.de_commit_foldings(verifier);
        self.de_query(
            intial_sub_com.as_ref(),
            &func_sub_com_vec,
            &fold_sub_com_vec,
        )
    }
}
