use ark_ff::UniformRand;
use ark_poly::polynomial::{univariate::DensePolynomial as UnivariatePolynomial, Polynomial};
use ark_poly::DenseUVPolynomial;
use ark_poly::EvaluationDomain;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use de_network::{DeMultiNet as Net, DeNet, DeSerNet};
use fri::deprover::DeFRIProver;
use fri::prover::BatchProver;
use fri::verifier::BatchFRIVerifier;
use std::path::PathBuf;
use std::time::Instant;
use structopt::StructOpt;
use utils::fiat_shamir::RandomOracle;
use utils::helper::Helper;
use utils::merkle_tree::MERKLE_ROOT_SIZE;
use utils::{goldilocks::Goldilocks as T, CODE_RATE, SECURITY_BITS};

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// Id
    id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn init() -> (usize, usize, usize, usize) {
    let opt = Opt::from_args();
    println!("{:?}", opt);

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);
    let num_parties = Net::n_parties();
    assert!(num_parties.is_power_of_two());

    let sub_prover_id = Net::party_id();
    let variable_num: usize = 22;

    let degree: usize = (1 << variable_num) - 1;
    assert!(
        (degree + 1) % num_parties == 0,
        "Polynomial size must be divisible by num_parties"
    );
    (degree, variable_num, num_parties, sub_prover_id)
}

// fn test_distribute() {
//     let len = 16;
//     let id = Net::party_id();
//     let vec: Vec<u16> = (0..len).map(|i| (id as u16) << 14 | (i as u16)).collect();

//     let first = Net::distribute(&vec[..len / 2], Net::n_parties());
//     let second = Net::distribute(&vec[len / 2..], Net::n_parties());

//     if Net::am_master() {
//         println!("first size: {} x {}", first.len(), first[0].len());
//         for vec in &first {
//             for num in vec {
//                 println!("first: {:016b}", num);
//             }
//         }

//         println!("second size: {} x {}", second.len(), second[0].len());
//         for vec in &second {
//             for num in vec {
//                 println!("second : {:016b}", num);
//             }
//         }
//     }
// }

fn main() {
    let (degree, variable_num, num_parties, sub_prover_id) = init();

    // test_distribute();
    // test_exchange();

    let mut rng = StdRng::seed_from_u64(0u64);

    let (polys, sub_poly) = if Net::am_master() {
        //generate random polynomials
        let mut polys = Vec::new();

        for _ in 0..num_parties {
            let poly = UnivariatePolynomial::rand(degree, &mut rng);
            let point = T::rand(&mut rng);
            let _eval = poly.evaluate(&point);
            polys.push(poly);
        }
        //distribute polynomial to sub parties
        (Some(polys.clone()), Net::recv_from_master(Some(polys)))
    } else {
        //receive polynomial from master
        (None, Net::recv_from_master(None))
    };

    // println!("id: {}, point: {}, eval: {}", Net::party_id(), point, eval);

    let mut interpolate_cosets =
        vec![EvaluationDomain::new_coset(1 << (variable_num + CODE_RATE), T::from(1)).unwrap()];
    for i in 1..variable_num {
        interpolate_cosets.push(Helper::pow(&interpolate_cosets[i - 1], 2));
    }

    let setup_size_bytes_recv = Net::stats().bytes_recv;
    let setup_size_bytes_sent = Net::stats().bytes_sent;

    // commit
    let oracle = if Net::am_master() {
        Some(RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE))
    } else {
        None
    };

    let time = Instant::now();
    let mut de_prover = DeFRIProver::new(
        sub_prover_id,
        variable_num,
        &interpolate_cosets,
        sub_poly,
        oracle.as_ref(),
    );

    // 32 bytes = 256 bit
    let (com, sub_com) = de_prover.de_commit_polynomial();
    println!(
        "Prover {:?} commit time: {:?}",
        sub_prover_id,
        time.elapsed()
    );

    if Net::am_master() {
        debug_assert_eq!(
            com.unwrap(),
            BatchProver::new(
                variable_num,
                &interpolate_cosets,
                &polys.unwrap(),
                &oracle.clone().unwrap(),
            )
            .commit_polynomial()
        );
    }

    // open
    let time = Instant::now();
    let mut verifier = if Net::am_master() {
        Some(BatchFRIVerifier::new(
            variable_num,
            &interpolate_cosets,
            com.unwrap(),
            &oracle.unwrap(),
        ))
    } else {
        None
    };

    let proof = de_prover.de_open(sub_com, verifier.as_mut());
    println!("Prover {:?} open time: {:?}", sub_prover_id, time.elapsed());

    if Net::am_master() {
        println!(
            "id: {}, Net::stats().bytes_recv: {}",
            sub_prover_id,
            Net::stats().bytes_recv - setup_size_bytes_recv
        );
        println!(
            "id: {}, Net::stats().bytes_sent: {}",
            sub_prover_id,
            Net::stats().bytes_sent - setup_size_bytes_sent
        );
    }

    // verify
    if Net::am_master() {
        let proof_size = proof.0.proof_size()
            + proof.1.iter().map(|x| x.proof_size()).sum::<usize>()
            + (variable_num - 1) * MERKLE_ROOT_SIZE;
        println!("Proof size: {:?} KB", proof_size / 1024);
        let time = Instant::now();
        assert!(verifier.unwrap().verify(&proof));
        println!("Verify time: {:?}", time.elapsed());
    }
}
