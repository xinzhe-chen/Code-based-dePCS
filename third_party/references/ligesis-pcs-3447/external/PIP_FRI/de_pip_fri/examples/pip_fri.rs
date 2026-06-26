use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::{end_timer, start_timer};
use de_pip_fri::prover::Prover;
use de_pip_fri::verifier::Verifier;
use std::vec;
use utils::fiat_shamir::RandomOracle;
use utils::helper::MultilinearPolynomial;
use utils::interpolate_vecs_value::{get_poly_num, get_sub_variable_num, get_tensor};
use utils::{goldilocks::Goldilocks as T, CODE_RATE, SECURITY_BITS};
use utils::{helper::Helper, merkle_tree::MERKLE_ROOT_SIZE};

fn main() {
    let variable_num: usize = 20;
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

    let step = start_timer!(|| "commit");
    let mut prover = Prover::new(
        sub_variable_num,
        &interpolate_cosets,
        polynomial,
        &oracle,
        &tensor,
    );

    // commit
    let commitment = prover.commit_polynomial();
    end_timer!(step);

    let mut verifier = Verifier::new(
        sub_variable_num,
        commitment,
        &interpolate_cosets,
        &oracle,
        &sub_open_point.to_vec(),
        &tensor,
    );

    // open
    let step = start_timer!(|| "open");
    let (polynomial_proof, folding_proof, function_proof) =
        prover.open(&sub_open_point.to_vec(), &mut verifier);
    end_timer!(step);

    // verify
    let step = start_timer!(|| "verify");
    let is_valid = verifier.verify(&polynomial_proof, &folding_proof, &function_proof, eval);
    assert!(is_valid);
    end_timer!(step);

    // proof_size
    let proof_size = folding_proof.iter().map(|x| x.proof_size()).sum::<usize>()
        + polynomial_proof.proof_size()
        + function_proof.iter().map(|x| x.proof_size()).sum::<usize>()
        + (2 * sub_variable_num - 3) * MERKLE_ROOT_SIZE
        + 2 * size_of::<T>();
    println!("proof size is: {:?}", proof_size / 1024);
}
