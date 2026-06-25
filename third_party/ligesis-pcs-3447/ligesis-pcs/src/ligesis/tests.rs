use super::*;
use ark_poly::MultilinearExtension;
use ark_std::{test_rng, UniformRand};
use FGoldilocks as F;

#[test]
fn test_ligesis_pcs() {
    let mut rng = test_rng();
    let mu = 18;

    let srs = LigeSISPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeSISPCS::<F>::setup(&srs).unwrap();

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(mu, &mut rng));
    let (com, advice) = LigeSISPCS::<F>::commit(&pp, &poly).unwrap();
    let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();

    let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_test");
    let proof = LigeSISPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = LigeSISPCS::<F>::compute_value_from_proof(mu - mu / 2, &point, &proof);

    let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_test");
    let res = LigeSISPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();

    assert!(res);
    assert_eq!(eval_mle_poly(&poly.evaluations, &point), value);
}

#[test]
fn test_ligesis_pcs_variable_size() {
    let mut rng = test_rng();
    let mu = 18;
    let actual_vars = 14;

    let srs = LigeSISPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeSISPCS::<F>::setup(&srs).unwrap();

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(actual_vars, &mut rng));
    let (com, advice) = LigeSISPCS::<F>::commit(&pp, &poly).unwrap();
    let point: Vec<F> = (0..actual_vars).map(|_| F::rand(&mut rng)).collect();

    let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_test");
    let proof = LigeSISPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = LigeSISPCS::<F>::compute_value_from_proof(mu - mu / 2, &point, &proof);

    let mut transcript = IOPTranscript::<F>::new(b"ligesis_pcs_test");
    let res = LigeSISPCS::<F>::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();

    assert!(res);
    assert_eq!(eval_mle_poly(&poly.evaluations, &point), value);
}

#[test]
fn test_ligesis_ext_pcs() {
    let mut rng = test_rng();
    let mu = 18;

    let srs = LigeSISPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = LigeSISPCS::<F>::setup(&srs).unwrap();

    let poly = Arc::new(DenseMultilinearExtension::<F>::rand(mu, &mut rng));
    let (com, advice) = LigeSISPCS::<F>::commit(&pp, &poly).unwrap();
    let point: Vec<F> = (0..mu).map(|_| F::rand(&mut rng)).collect();

    // Use extension field open
    let mut transcript = IOPTranscript::<F>::new(b"ligesis_ext_pcs_test");
    let ext_proof = ligesis_open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = poly.evaluate(&point).unwrap();

    // Use extension field verify
    let mut transcript = IOPTranscript::<F>::new(b"ligesis_ext_pcs_test");
    let res = ligesis_verify(&vp, &com, &point, &value, &ext_proof, &mut transcript).unwrap();

    assert!(res);
}
