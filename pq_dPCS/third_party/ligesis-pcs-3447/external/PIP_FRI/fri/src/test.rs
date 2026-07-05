#[cfg(test)]
mod tests {
    use std::vec;

    use crate::prover::{BatchProver, Prover};
    use crate::verifier::{BatchVerifier, Verifier};
    use ark_ff::UniformRand;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::EvaluationDomain;
    use utils::{goldilocks::Goldilocks as T, CODE_RATE, SECURITY_BITS};
    // use ark_ff::PrimeField;
    use ark_poly::polynomial::{univariate::DensePolynomial as UnivariatePolynomial, Polynomial};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use utils::fiat_shamir::RandomOracle;
    use utils::{helper::Helper, merkle_tree::MERKLE_ROOT_SIZE};

    #[test]
    fn fri_pcs_test() {
        let variable_num: usize = 20;
        let degree: usize = (1 << variable_num) - 1;
        let mut rng = StdRng::seed_from_u64(0u64);
        let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
        let point = T::rand(&mut rng);
        let eval = polynomial.evaluate(&point);

        let mut interpolate_cosets =
            vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
        for i in 1..variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
        }

        // commit
        let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle);
        // 32 bytes = 256 bit
        let com = prover.commit_polynomial();

        // open
        let mut verifier = Verifier::new(variable_num, &interpolate_cosets, com, &oracle, point);
        let proof = prover.open(point, eval, &mut verifier);

        // verify
        assert!(verifier.verify(&proof, eval));

        // proof size
        let proof_size = proof.iter().map(|x| x.proof_size()).sum::<usize>()
            + (variable_num - 1) * MERKLE_ROOT_SIZE;
        println!(
            "first round proof size is {:?} KB ",
            proof[0].proof_size() / 1024
        );
        println!("proof size is {:?} KB", proof_size / 1024);
    }

    #[test]
    fn batch_fri_pcs_test() {
        let poly_num = 4;
        let variable_num: usize = 21;
        let degree: usize = (1 << variable_num) - 1;
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut polynomials = vec![];
        let mut points = vec![];
        let mut evals = vec![];
        for _ in 0..poly_num {
            let polynomial = UnivariatePolynomial::rand(degree, &mut rng);
            let point = T::rand(&mut rng);
            let eval = polynomial.evaluate(&point);
            polynomials.push(polynomial);
            points.push(point);
            evals.push(eval);
        }

        let mut interpolate_cosets =
            vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
        for i in 1..variable_num {
            interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
        }

        // commit
        let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
        let mut prover = BatchProver::new(variable_num, &interpolate_cosets, &polynomials, &oracle);
        // 32 bytes = 256 bit
        let com = prover.commit_polynomial();

        // open
        let mut verifier =
            BatchVerifier::new(variable_num, &interpolate_cosets, com, &oracle, &points);
        let proof = prover.open(&points, &evals, &mut verifier);

        // verify
        assert!(verifier.verify(&proof, &evals));

        // proof size
        let proof_size = proof.0.proof_size()
            + proof.1.iter().map(|x| x.proof_size()).sum::<usize>()
            + (variable_num - 1) * MERKLE_ROOT_SIZE;
        println!("proof size is {:?} KB", proof_size / 1024);
    }
}
