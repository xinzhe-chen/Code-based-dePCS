use ark_ff::PrimeField;
use merlin::Transcript;
use rand::Rng;

// This is a simple random oracle from round and query number, 
// generating folding challenges and query_list
#[derive(Debug, Clone)]
pub struct RandomOracle<T: PrimeField> {
    pub beta: T,
    pub rlc: T,
    pub folding_challenges: Vec<T>,
    pub query_list: Vec<usize>,
}

impl<T: PrimeField> RandomOracle<T> {
    pub fn new(total_round: usize, query_num: usize) -> Self {
        let mut rng = rand::thread_rng();
        RandomOracle {
            beta: T::rand(&mut rng),
            rlc: T::rand(&mut rng),
            folding_challenges: (0..total_round)
                .into_iter()
                .map(|_| T::rand(&mut rng))
                .collect(),
            query_list: (0..query_num).into_iter().map(|_| rng.gen()).collect(),
        }
    }
}

// An implementation of Fiat-Shamir from merlin
// generating random query location
pub trait ProofTranscript<T: PrimeField> {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]);
  fn append_scalar(&mut self, label: &'static [u8], scalar: &T);
  fn append_scalars(&mut self, label: &'static [u8], scalars: &[T]);
  fn append_root(&mut self, label: &'static [u8], root: &[u8]);
//   fn append_point(&mut self, label: &'static [u8], point: &P::G1);
//   fn append_points(&mut self, label: &'static [u8], points: &[P::G1]);
  fn challenge_scalar(&mut self, label: &'static [u8]) -> T;
  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<T>;
}

impl<T: PrimeField> ProofTranscript<T> for Transcript {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]) {
    self.append_message(b"protocol-name", protocol_name);
  }

  fn append_scalar(&mut self, label: &'static [u8], scalar: &T) {
    let mut buf = vec![];
    scalar.serialize_uncompressed(&mut buf).unwrap();
    self.append_message(label, &buf);
  }

  fn append_scalars(&mut self, label: &'static [u8], scalars: &[T]) {
    self.append_message(label, b"begin_append_vector");
    for item in scalars.iter() {
      <Self as ProofTranscript<T>>::append_scalar(self, label, item);
    }
    self.append_message(label, b"end_append_vector");
  }

  // directly use &merkle_root is ok
  fn append_root(&mut self, label: &'static [u8], root: &[u8]) {
    self.append_message(label, root);
  }


//   fn append_point(&mut self, label: &'static [u8], point: &P::G1) {
//     let mut buf = vec![];
//     point.serialize_uncompressed(&mut buf).unwrap();
//     self.append_message(label, &buf);
//   }

//   fn append_points(&mut self, label: &'static [u8], points: &[P::G1]) {
//     self.append_message(label, b"begin_append_vector");
//     for item in points.iter() {
//       <Self as ProofTranscript<P>>::append_point(self, label, item);
//     }
//     self.append_message(label, b"end_append_vector");
//   }

  fn challenge_scalar(&mut self, label: &'static [u8]) -> T {
    let mut buf = [0u8; 64];
    self.challenge_bytes(label, &mut buf);
    T::from_le_bytes_mod_order(&buf)
  }

  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<T> {
    (0..len)
      .map(|_i| <Self as ProofTranscript<T>>::challenge_scalar(self, label))
      .collect::<Vec<T>>()
  }
}