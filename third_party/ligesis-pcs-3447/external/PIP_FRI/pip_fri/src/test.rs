#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::{prover::Prover, verifier::Verifier};
    use ark_ff::UniformRand;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use utils::fiat_shamir::RandomOracle;
    use utils::goldilocks::Goldilocks as T;
    use utils::helper::Helper;
    use utils::helper::MultilinearPolynomial;
    use utils::interpolate_vecs_value::*;
    use utils::merkle_tree::MERKLE_ROOT_SIZE;
    use utils::{CODE_RATE, SECURITY_BITS};

    #[test]
    fn pip_fri_test() {
        let variable_num: usize = 14;
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // Divide and generate public informations
        let poly_num = get_poly_num(&polynomial);
        // let poly_num = 2;
        println!("poly num is: {:?}", poly_num);
        let sub_variable_num = get_sub_variable_num(&polynomial);
        let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
        // w_1, w_2, ...,
        let tensor = get_tensor(&remaining_var.to_vec());

        // Setup
        let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
            1 << (sub_variable_num + CODE_RATE),
            T::rand(&mut rng),
        )
        .unwrap()];
        for i in 1..sub_variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
        }
        let oracle = RandomOracle::new(sub_variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = Prover::new(
            sub_variable_num,
            &interpolate_cosets,
            polynomial,
            &oracle,
            &tensor,
        );

        // commit
        let commitment = prover.commit_polynomial();
        let mut verifier = Verifier::new(
            sub_variable_num,
            commitment,
            &interpolate_cosets,
            &oracle,
            &sub_open_point.to_vec(),
            &tensor,
        );

        // open
        let (polynomial_proof, folding_proof, function_proof) =
            prover.open(&sub_open_point.to_vec(), &mut verifier);

        // verify
        let is_valid = verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof_size
        let proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + polynomial_proof.proof_size()
            + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
            + 2 * size_of::<T>();
        println!("proof size is: {:?}", proof_size / 1024);
    }

    fn output_proof_size(variable_num: usize) -> (usize, usize) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // Divide and generate public informations
        let poly_num = get_poly_num(&polynomial);
        println!("poly num is: {:?}", poly_num);
        let sub_variable_num = get_sub_variable_num(&polynomial);
        let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
        // w_1, w_2, ...,
        let tensor = get_tensor(&remaining_var.to_vec());

        // Setup
        let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
            1 << (sub_variable_num + CODE_RATE),
            T::rand(&mut rng),
        )
        .unwrap()];
        for i in 1..sub_variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
        }
        let oracle = RandomOracle::new(sub_variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = Prover::new(
            sub_variable_num,
            &interpolate_cosets,
            polynomial,
            &oracle,
            &tensor,
        );

        // commit
        let commitment = prover.commit_polynomial();
        let mut verifier = Verifier::new(
            sub_variable_num,
            commitment,
            &interpolate_cosets,
            &oracle,
            &sub_open_point.to_vec(),
            &tensor,
        );

        // open
        let (polynomial_proof, folding_proof, function_proof) =
            prover.open(&sub_open_point.to_vec(), &mut verifier);

        // verify
        let is_valid = verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof_size
        (
            folding_proof
                .iter()
                .map(|x| x.path_proof_size())
                .sum::<usize>()
                + polynomial_proof.path_proof_size()
                + function_proof
                    .iter()
                    .map(|x| x.path_proof_size())
                    .sum::<usize>(),
            folding_proof
                .iter()
                .map(|x| x.field_proof_size())
                .sum::<usize>()
                + polynomial_proof.field_proof_size()
                + function_proof
                    .iter()
                    .map(|x| x.field_proof_size())
                    .sum::<usize>()
                + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
                + 2 * size_of::<T>(),
        )
    }

    #[test]
    fn test_proof_size() {
        for i in 17..=20 {
            let (path_proof_size, field_proof_size) = output_proof_size(i);
            println!(
                "PIP-FRI (path, field)_proof_size of {} variables is ({}, {}) Kbytes",
                i,
                path_proof_size / 1024,
                field_proof_size / 1024
            );
            println!(
                "PIP-FRI total_proof_size of {} variables is {} Kbytes",
                i,
                (path_proof_size + field_proof_size) / 1024
            );
        }
    }
}
