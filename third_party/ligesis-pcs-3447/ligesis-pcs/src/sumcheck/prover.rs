// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Prover subroutines for a SumCheck protocol.

use super::SumCheckProver;
use crate::{
    barycentric_weights, extrapolate,
    iop_errors::PolyIOPErrors,
    structs::{IOPProverMessage, IOPProverState},
};
use arithmetic::{bind_poly_var_bot, VirtualPolynomial};
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use std::sync::Arc;

impl<F: PrimeField> SumCheckProver<F> for IOPProverState<F> {
    type VirtualPolynomial = VirtualPolynomial<F>;
    type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn prover_init(polynomial: Self::VirtualPolynomial) -> Result<Self, PolyIOPErrors> {
        if polynomial.aux_info.num_variables == 0 {
            return Err(PolyIOPErrors::InvalidParameters(
                "Attempt to prove a constant.".to_string(),
            ));
        }

        Ok(Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            extrapolation_aux: (1..polynomial.aux_info.max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect(),
            poly: polynomial,
        })
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PolyIOPErrors> {
        if self.round >= self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::InvalidProver(
                "Prover is not active".to_string(),
            ));
        }

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)

        if let Some(chal) = challenge {
            if self.round == 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            self.poly
                .flattened_ml_extensions
                .iter_mut()
                .for_each(|mle| bind_poly_var_bot(Arc::get_mut(mle).unwrap(), &r));
        }

        self.round += 1;

        let products_list = self.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        products_list.iter().for_each(|(coefficient, products)| {
            let mut sum = (0..1 << (self.poly.aux_info.num_variables - self.round))
                .fold(
                    vec![F::zero(); products.len() + 1],
                    |mut acc, b| {
                        let mut buf: Vec<(F, F)> = products
                            .iter()
                            .map(|f| {
                                let table = &self.poly.flattened_ml_extensions[*f];
                                let eval = table[b << 1];
                                let step = table[(b << 1) + 1] - table[b << 1];
                                (eval, step)
                            })
                            .collect();
                        acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                        acc[1..].iter_mut().for_each(|acc| {
                            buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                            *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                        });
                        acc
                    },
                );
            sum.iter_mut().for_each(|sum| *sum *= coefficient);
            let extraploation = (0..self.poly.aux_info.max_degree - products.len())
                .map(|i| {
                    let (points, weights) = &self.extrapolation_aux[products.len() - 1];
                    let at = F::from((products.len() + 1 + i) as u64);
                    extrapolate(points, weights, &sum, &at)
                })
                .collect::<Vec<_>>();
            products_sum
                .iter_mut()
                .zip(sum.iter().chain(extraploation.iter()))
                .for_each(|(products_sum, sum)| *products_sum += sum);
        });

        Ok(IOPProverMessage {
            evaluations: products_sum,
        })
    }

    fn get_final_mle_evaluations(&mut self, challenge: F) -> Result<Vec<F>, PolyIOPErrors> {
        if self.round != self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::InvalidProver(
                "Prover is not finished yet".to_string(),
            ));
        }
        self.challenges.push(challenge);

        let claims = self
            .poly
            .flattened_ml_extensions
            .iter_mut()
            .map(|mle| {
                let mle = Arc::get_mut(mle).unwrap();
                bind_poly_var_bot(mle, &challenge);
                mle.evaluations[0]
            })
            .collect();
        Ok(claims)
    }
}
