#[cfg(test)]
mod tests {
    use ark_ff::{BigInt, BigInteger, FftField, Field, PrimeField, Zero};
    // Now we'll use the prime field underlying the BLS12-381 G1 curve.
    // use ark_test_curves::bls12_381::Fq as Fq;
    // use utils::fp17::Fp17 as Fq;
    use ark_std::{One, UniformRand};
    use rand::thread_rng;
    use utils::goldilocks::Goldilocks as Fq;

    use ark_poly::{
        polynomial::{univariate::DensePolynomial as UnivariatePolynomial, Polynomial},
        DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    };

    #[test]
    fn field_test() {
        let a = Fq::from(9);
        let b = Fq::from(10);

        // assert_eq!(a, Fq::from(26));          // 26 =  9 mod 17
        // assert_eq!(a - b, Fq::from(16));      // -1 = 16 mod 17
        // assert_eq!(a + b, Fq::from(2));       // 19 =  2 mod 17
        // assert_eq!(a * b, Fq::from(5));       // 90 =  5 mod 17
        // assert_eq!(a.square(), Fq::from(13)); // 81 = 13 mod 17
        // assert_eq!(b.double(), Fq::from(3));  // 20 =  3 mod 17
        assert_eq!(a / b, a * b.inverse().unwrap()); // need to unwrap since `b` could be 0 which is not invertible
                                                     // assert_eq!(a.pow(b.into_bigint()), Fq::from(13)); // pow takes BigInt as input

        let generator = Fq::GENERATOR;
        println!("element is: {:?}", generator);

        //// Working with Randomness
        let mut rng = thread_rng();
        let a = Fq::rand(&mut rng);
        // We can access the prime modulus associated with `F`:
        let modulus = <Fq as PrimeField>::MODULUS;
        assert_eq!(a.pow(&modulus), a);

        // We can convert field elements to integers in the range [0, MODULUS - 1]:
        let one: num_bigint::BigUint = Fq::one().into();
        assert_eq!(one, num_bigint::BigUint::one());

        // We can construct field elements from an arbitrary sequence of bytes:
        let n = Fq::from_le_bytes_mod_order(&modulus.to_bytes_le());
        assert_eq!(n, Fq::zero());

        let polynomial =
            UnivariatePolynomial::from_coefficients_vec(vec![Fq::from(1), Fq::from(2)]);
        let eval = polynomial.evaluate(&Fq::from(2));
        assert_eq!(eval, Fq::from(5));

        // let domain = GeneralEvaluationDomain::new_coset(4, Fq::GENERATOR).unwrap();
        // println!("first element is {:?}", domain.element(0));

        // let evals = polynomial.evaluate_over_domain_by_ref(domain);
        // println!("first element in evals is {:?}", evals[0]);

        // let inter_poly = evals.interpolate_by_ref();
        // assert_eq!(polynomial, inter_poly);

        // evals[0].into_bigint().to_bytes_be();
    }
}

fn main() {}
