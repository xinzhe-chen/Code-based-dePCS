use pq_pcs::DistributedPcsParams;
use pq_transcript::Transcript;

pub trait Piop {
    type Statement;
    type Witness;
    type Proof;
    type Metrics;
    type Error;

    fn prove_interactive<T: Transcript>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        workers: usize,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify_interactive<T: Transcript>(
        statement: &Self::Statement,
        proof: &Self::Proof,
        pcs_params: DistributedPcsParams,
        transcript: &mut T,
    ) -> Result<Self::Metrics, Self::Error>;
}
