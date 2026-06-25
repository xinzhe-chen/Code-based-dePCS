#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::{prover::One2ManyProver, verifier::One2ManyVerifier};
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

    #[test]
    fn polyfrim_test() {
        let variable_num: usize = 14;
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // setup
        let mut interpolate_cosets = vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
        for i in 1..variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
        }

        let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = One2ManyProver::new(variable_num, &interpolate_cosets, polynomial, &oracle);

        // commit
        let commit = prover.commit_polynomial();
        let mut verifier = One2ManyVerifier::new(
            variable_num,
            &interpolate_cosets,
            commit,
            &oracle,
            &point,
        );

        // open
        let (folding_proof, function_proof) = prover.open(&mut verifier, &point);
    
        // verify
        let is_valid = verifier.verify(&folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof size
        let proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            // p only has \mu - 1 polynomials, and \mu - 2 roots
            // f involve \mu polynomials, and \mu - 1 roots
            + (2 * variable_num - 3) * MERKLE_ROOT_SIZE
            + size_of::<T>() * 2;
        println!("proof size is {:?} KB", proof_size / 1024);

        let path_proof_size = folding_proof.iter().map(|x| x.path_proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.path_proof_size()).sum::<usize>();
        println!("path proof size is {:?} KB", path_proof_size / 1024);

        let field_proof_size = folding_proof.iter().map(|x| x.field_proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.field_proof_size()).sum::<usize>();
        println!("field proof size is {:?} KB", field_proof_size / 1024);
    }

    fn output_proof_size(variable_num: usize) -> (usize, usize) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = MultilinearPolynomial::rand(variable_num);
        let point = (0..variable_num)
            .map(|_| T::rand(&mut rng))
            .collect::<Vec<T>>();
        let eval = polynomial.evaluate(&point);

        // setup
        let mut interpolate_cosets = vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
        for i in 1..variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i-1], 2));
        }

        let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = One2ManyProver::new(variable_num, &interpolate_cosets, polynomial, &oracle);

        // commit
        let commit = prover.commit_polynomial();
        let mut verifier = One2ManyVerifier::new(
            variable_num,
            &interpolate_cosets,
            commit,
            &oracle,
            &point,
        );

        // open
        let (folding_proof, function_proof) = prover.open(&mut verifier, &point);
    
        // verify
        let is_valid = verifier.verify(&folding_proof, &function_proof, eval);
        assert!(is_valid);

        // proof size
        let proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
            // p only has \mu - 1 polynomials, and \mu - 2 roots
            // f involve \mu polynomials, and \mu - 1 roots
            + (2 * variable_num - 3) * MERKLE_ROOT_SIZE
            + size_of::<T>() * 2;
        println!("proof size is {:?} KB", proof_size / 1024);

        let path_proof_size = folding_proof.iter().map(|x| x.path_proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.path_proof_size()).sum::<usize>();

        let field_proof_size = folding_proof.iter().map(|x| x.field_proof_size()).sum::<usize>()
            + function_proof.iter().map(|x| x.field_proof_size()).sum::<usize>();

        (path_proof_size, field_proof_size)
    }


    #[test]
    fn test_proof_size() {
        for i in 18..=23 {
            let (path_proof_size, field_proof_size) = output_proof_size(i);
            println!(
                "PIP-FRI (path, field)_proof_size of {} variables is ({}, {}) Kbytes",
                i, path_proof_size / 1024, field_proof_size / 1024
            );
            println!(
                "PIP-FRI total_proof_size of {} variables is {} Kbytes",
                i, (path_proof_size + field_proof_size) / 1024
            );
        }
    }
}