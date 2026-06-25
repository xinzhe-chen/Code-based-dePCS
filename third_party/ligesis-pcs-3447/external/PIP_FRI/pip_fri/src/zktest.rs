#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::{zkprover::ZKProver, zkverifier::ZKVerifier};
    use ark_ff::{Field, UniformRand};
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};
    use utils::helper::MultilinearPolynomial;
    use utils::merkle_tree::MERKLE_ROOT_SIZE;
    use utils::fiat_shamir::RandomOracle;
    use utils::{CODE_RATE, SECURITY_BITS};
    use utils::goldilocks::Goldilocks as T;
    use utils::helper::Helper;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use utils::interpolate_vecs_value::*;

    #[test]
    fn zk_pip_fri_test() {
        let variable_num: usize = 14;
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // Divide and generate public informations
        // let poly_num = get_poly_num(&polynomial);
        // println!("poly num is: {:?}", poly_num);
        let sub_variable_num = get_sub_variable_num(&polynomial);
        let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
        let mut sub_open_point = sub_open_point.to_vec();
        sub_open_point.push(T::ZERO);
        // w_1, w_2, ...,
        let tensor = get_tensor(&remaining_var.to_vec());

        // Setup
        let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
            1 << (sub_variable_num + 1 + CODE_RATE),
            T::rand(&mut rng),
        ).unwrap()];
        for i in 1..(sub_variable_num + 1) {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
        }
        let oracle = RandomOracle::new(sub_variable_num + 1, SECURITY_BITS / CODE_RATE);
        let mut prover = ZKProver::new(sub_variable_num + 1, &interpolate_cosets, polynomial, &oracle, &tensor);

        // commit
        let commitment = prover.commit_polynomial();
        let mut verifier = ZKVerifier::new(sub_variable_num + 1, commitment, &interpolate_cosets, &oracle, &sub_open_point, &tensor);

        // open
        let (polynomial_proof, folding_proof, function_proof) = prover.open(&sub_open_point, &mut verifier);
    
        // verify
        let is_valid = verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof_size
        let proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + polynomial_proof.proof_size()
            + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + (2 * (sub_variable_num + 1) - 3) * MERKLE_ROOT_SIZE
            + 2 * size_of::<T>();
        println!("proof size is: {:?}KB", proof_size / 1024);
    }

    fn output_proof_size(variable_num: usize) -> (usize, usize) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // Divide and generate public informations
        // let poly_num = get_poly_num(&polynomial);
        let poly_num = get_poly_num(&polynomial);
        println!("poly num is: {:?}", poly_num);
        let sub_variable_num = get_sub_variable_num(&polynomial);
        let (sub_open_point, remaining_var) = point.split_at(sub_variable_num);
        let mut sub_open_point = sub_open_point.to_vec();
        sub_open_point.push(T::ZERO);
        // w_1, w_2, ...,
        let tensor = get_tensor(&remaining_var.to_vec());

        // Setup
        let mut interpolate_cosets = vec![GeneralEvaluationDomain::new_coset(
            1 << (sub_variable_num + 1 + CODE_RATE),
            T::rand(&mut rng),
        ).unwrap()];
        for i in 1..(sub_variable_num + 1) {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
        }
        let oracle = RandomOracle::new(sub_variable_num + 1, SECURITY_BITS / CODE_RATE);
        let mut prover = ZKProver::new(sub_variable_num + 1, &interpolate_cosets, polynomial, &oracle, &tensor);

        // commit
        let commitment = prover.commit_polynomial();
        let mut verifier = ZKVerifier::new(sub_variable_num + 1, commitment, &interpolate_cosets, &oracle, &sub_open_point, &tensor);

        // open
        let (polynomial_proof, folding_proof, function_proof) = prover.open(&sub_open_point, &mut verifier);
    
        // verify
        let is_valid = verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof_size
        (folding_proof.iter().map(|x| x.path_proof_size()).sum::<usize>()
            + polynomial_proof.path_proof_size()
            + function_proof.iter().map(|x| x.path_proof_size()).sum::<usize>(),
        folding_proof.iter().map(|x| x.field_proof_size()).sum::<usize>()
            + polynomial_proof.field_proof_size()
            + function_proof.iter().map(|x| x.field_proof_size()).sum::<usize>()
            + (2 * (sub_variable_num + 1) - 3) * MERKLE_ROOT_SIZE
            // and s(x)
            + 3 * size_of::<T>())
    }

    #[test]
    fn test_proof_size() {
        for i in 18..=18 {
            let (path_proof_size, field_proof_size) = output_proof_size(i);
            println!(
                "zk-PIP-FRI (path, field)_proof_size of {} variables is ({}, {}) Kbytes",
                i, path_proof_size / 1024, field_proof_size / 1024
            );
        }
    }
}