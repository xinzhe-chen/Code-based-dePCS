#[cfg(test)]
mod tests {    
    use std::mem;

    use ark_ff::UniformRand;
    use ark_poly::EvaluationDomain;
    use utils::helper::MultilinearPolynomial;
    use utils::merkle_tree::MERKLE_ROOT_SIZE;
    use utils::fiat_shamir::RandomOracle;
    use utils::{CODE_RATE, SECURITY_BITS};
    use utils::goldilocks::Goldilocks as T;
    use utils::helper::Helper;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use crate::{zkprover::ZKFriProver, zkverifier::ZKFriVerifier};

    #[test]
    fn zk_virgo_test() {
        let variable_num = 14;
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::<T>::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let evaluation = polynomial.evaluate(&point);
        // must +2 for the security of FRI on s, s's degree is 2|H| + \lambda - 1
        let mut interpolate_cosets = vec![EvaluationDomain::new_coset(
            1 << (variable_num + CODE_RATE + 2),
            T::from(1),
        ).unwrap()];
        for i in 1..(variable_num + 2) {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
        }
        let random_oracle = RandomOracle::new(variable_num + 2, SECURITY_BITS / CODE_RATE);
        let vector_interpolation_coset = EvaluationDomain::new_coset(1 << variable_num, T::from(1)).unwrap();
        let mut prover = ZKFriProver::new(
            variable_num + 2,
            &interpolate_cosets,
            &vector_interpolation_coset,
            polynomial,
            &random_oracle,
        );

        // Commit
        let com = prover.commit_polynomial();

        // Open
        let mut verifier = ZKFriVerifier::new(
            variable_num + 2,
            &interpolate_cosets,
            &vector_interpolation_coset,
            com,
            &random_oracle,
        );
        verifier.get_open_point(&point);
        prover.commit_functions(&mut verifier, &point);
        prover.prove();
        prover.commit_foldings(&mut verifier);
        let (folding_proofs, function_us_proof, function_h_proof, v_value) = prover.query();

        // Verify
        let is_valid = verifier.verify(evaluation, &folding_proofs, &v_value, &function_us_proof, &function_h_proof);
        assert!(is_valid);

        // Proof size
        let proof_size = folding_proofs.iter().map(|x| x.proof_size()).sum::<usize>()
            + function_us_proof.proof_size()
            + function_h_proof.proof_size()
            + v_value.len() * (mem::size_of::<usize>() + size_of::<T>())
            + MERKLE_ROOT_SIZE * (variable_num + 1);
        println!("proof size is: {:?} KB", proof_size / 1024);
    }
}