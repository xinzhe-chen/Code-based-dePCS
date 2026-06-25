use arithmetic::{math::Math, VirtualPolynomial};
use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use clap::Parser;
use rand::{rngs::StdRng, SeedableRng};
use std::{ops::FnOnce, path::PathBuf, sync::Arc};

#[derive(Debug, Parser)]
#[command(name = "distributed_test")]
pub struct Opt {
    /// Party ID
    pub id: usize,

    /// Network config file path
    pub input: PathBuf,

    /// Number of polynomial variables
    #[arg(short, long, default_value_t = 20)]
    pub mu: usize,

    /// Override base_mu (DeepFold max_mu). If not specified, uses default
    /// formula.
    #[arg(long)]
    pub base_mu: Option<usize>,

    /// Override log_m (determines log_n = mu - log_m). If not specified, uses
    /// default formula.
    #[arg(long)]
    pub log_m: Option<usize>,

    /// Override code rate multiplier (e.g., 4 for 1/4 rate, 8 for 1/8 rate).
    /// Default: 4
    #[arg(long)]
    pub code_rate: Option<usize>,

    /// Number of iterations (runs multiple tests in single network session)
    #[arg(short, long, default_value_t = 1)]
    pub iterations: usize,

    /// Number of FRI query positions for benchmarks that expose a query count.
    #[arg(long, default_value_t = 282)]
    pub queries: usize,
}

pub(super) fn network_run<F>(func: F)
where
    F: FnOnce(Opt) -> (),
{
    let opt = Opt::parse();
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    func(opt);

    Net::deinit();
}

pub(super) fn d_evaluate<F: PrimeField>(
    poly: &VirtualPolynomial<F>,
    point: Option<&[F]>,
) -> Option<F> {
    if Net::am_master() {
        let num_party_vars = Net::n_parties().log_2() as usize;
        let point = point.unwrap();
        let nv = point.len() - num_party_vars;
        Net::recv_from_master_uniform(Some(point[..nv].to_vec()));

        let evals = poly
            .flattened_ml_extensions
            .iter()
            .map(|mle| mle.evaluate(&point[..nv]).unwrap())
            .collect::<Vec<_>>();

        let evals = Net::send_to_master(&evals).unwrap();
        let mle_evals = (0..evals[0].len())
            .map(|mle_index| {
                DenseMultilinearExtension::from_evaluations_vec(
                    num_party_vars,
                    evals
                        .iter()
                        .map(|party_evals| party_evals[mle_index])
                        .collect(),
                )
                .evaluate(&point[nv..])
                .unwrap()
            })
            .collect::<Vec<_>>();

        let result = poly
            .products
            .iter()
            .map(|(coeff, indices)| {
                *coeff * indices.iter().map(|index| mle_evals[*index]).product::<F>()
            })
            .sum();
        Some(result)
    } else {
        let point = Net::recv_from_master_uniform::<Vec<F>>(None);
        let evals = poly
            .flattened_ml_extensions
            .iter()
            .map(|mle| mle.evaluate(&point).unwrap())
            .collect::<Vec<_>>();
        Net::send_to_master(&evals);
        None
    }
}

pub(super) fn d_evaluate_mle<F: PrimeField>(
    poly: &Arc<DenseMultilinearExtension<F>>,
    point: Option<&[F]>,
) -> Option<F> {
    d_evaluate(&VirtualPolynomial::new_from_mle(poly, F::one()), point)
}

pub(super) fn test_rng() -> StdRng {
    let mut seed = [0u8; 32];
    seed[0] = Net::party_id() as u8;
    rand::rngs::StdRng::from_seed(seed)
}

pub(super) fn test_rng_deterministic() -> StdRng {
    let seed = [69u8; 32];
    rand::rngs::StdRng::from_seed(seed)
}
