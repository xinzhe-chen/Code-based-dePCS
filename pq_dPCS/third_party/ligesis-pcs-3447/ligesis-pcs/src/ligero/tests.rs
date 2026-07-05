use super::*;
use ark_bls12_381::Fr as F;
use ark_poly::MultilinearExtension;
use ark_std::{test_rng, UniformRand};

#[test]
fn test_ligero_pcs() {
    let mut rng = test_rng();
    let mu = 18;

    let srs = LigeroPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeroPCS::<F>::setup(&srs).unwrap();

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(mu, &mut rng));
    let (com, advice) = LigeroPCS::<F>::commit(&pp, &poly).unwrap();
    let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();

    let mut transcript = IOPTranscript::<F>::new(b"ligero_pcs_test");
    let proof = LigeroPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = LigeroPCS::<F>::compute_value_from_proof(pp.1, &point, &proof);

    let mut transcript = IOPTranscript::<F>::new(b"ligero_pcs_test");
    let res =
        LigeroPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();

    assert!(res);
}

#[test]
fn test_ligero_pcs_variable_size() {
    let mut rng = test_rng();
    let mu = 18;
    let actual_vars = 14;

    let srs = LigeroPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeroPCS::<F>::setup(&srs).unwrap();

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(actual_vars, &mut rng));
    let (com, advice) = LigeroPCS::<F>::commit(&pp, &poly).unwrap();
    let point: Vec<F> = (0..actual_vars).map(|_| F::rand(&mut rng)).collect();

    let mut transcript = IOPTranscript::<F>::new(b"ligero_pcs_test");
    let proof = LigeroPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = LigeroPCS::<F>::compute_value_from_proof(pp.1, &point, &proof);

    let mut transcript = IOPTranscript::<F>::new(b"ligero_pcs_test");
    let res =
        LigeroPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();

    assert!(res);
}
