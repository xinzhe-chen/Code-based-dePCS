use super::*;
use crate::rand::random_field_vector_from_rng;
use ark_bls12_381::Fr as F;
use ark_std::test_rng;

#[test]
fn test_deepfold_pcs() {
    let mut rng = test_rng();
    let mu = 8;

    let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = DeepFoldPCS::<F>::setup(srs).unwrap();

    let evals = random_field_vector_from_rng::<F>(1 << mu, &mut rng);
    let poly = Arc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(mu, evals));

    let (com, advice) = DeepFoldPCS::<F>::commit(&pp, &poly).unwrap();
    let point = random_field_vector_from_rng::<F>(mu, &mut rng);

    let mut transcript = IOPTranscript::new(b"test");
    let proof = DeepFoldPCS::<F>::open(&pp, &poly, &advice, &point, &mut transcript).unwrap();

    let value = DeepFoldPCS::compute_value_from_proof(&point, &proof);

    let mut transcript = IOPTranscript::new(b"test");
    let result =
        DeepFoldPCS::verify(&vp, &com, &point, &value, &proof, &mut transcript).unwrap();

    assert!(result);
    assert_eq!(eval_mle_poly(&poly.evaluations, &point), value);
}

#[test]
fn test_deepfold_pcs_batch_open() {
    let mut rng = test_rng();
    let mu = 8;
    let num_polys = 3;

    let srs = DeepFoldPCS::<F>::gen_srs_for_testing(&mut rng, mu).unwrap();
    let (pp, vp) = DeepFoldPCS::<F>::setup(srs).unwrap();

    // Create multiple polynomials
    let polys: Vec<_> = (0..num_polys)
        .map(|_| {
            let evals = random_field_vector_from_rng::<F>(1 << mu, &mut rng);
            Arc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(mu, evals))
        })
        .collect();

    // Commit to each polynomial
    let (coms, advices): (Vec<_>, Vec<_>) = polys
        .iter()
        .map(|poly| DeepFoldPCS::<F>::commit(&pp, poly).unwrap())
        .unzip();

    // Generate different points for each polynomial
    let points: Vec<Vec<F>> = (0..num_polys)
        .map(|_| random_field_vector_from_rng::<F>(mu, &mut rng))
        .collect();

    // Compute expected values
    let evals: Vec<F> = polys
        .iter()
        .zip(points.iter())
        .map(|(poly, point)| eval_mle_poly(&poly.evaluations, point))
        .collect();

    // Batch open
    let mut transcript = IOPTranscript::new(b"test_batch");
    let advice_refs: Vec<_> = advices.iter().collect();
    let batch_proof = DeepFoldPCS::<F>::batch_open(
        &pp,
        polys.clone(),
        &advice_refs,
        &points,
        &evals,
        &mut transcript,
    )
    .unwrap();

    // Batch verify
    let mut transcript = IOPTranscript::new(b"test_batch");
    let result =
        DeepFoldPCS::<F>::batch_verify(&vp, &coms, &points, &batch_proof, &mut transcript).unwrap();

    assert!(result);
}
