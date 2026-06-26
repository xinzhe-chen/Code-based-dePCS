use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

#[derive(Clone)]
pub struct ReedSolomon<F: FftField> {
    n: usize,
    domain: GeneralEvaluationDomain<F>,
}

impl<F: FftField> ReedSolomon<F> {
    pub fn new(n: usize, rs_len: usize) -> Self {
        let domain = GeneralEvaluationDomain::<F>::new(rs_len).unwrap();
        Self { n, domain }
    }

    pub fn encode(&self, v: &Vec<F>) -> Vec<F> {
        self.domain.fft(v)
    }

    pub fn get_n(&self) -> usize {
        self.n
    }

    pub fn get_k(&self) -> usize {
        self.domain.size()
    }

    pub fn get_generator(&self) -> F {
        self.domain.element(1)
    }
}
