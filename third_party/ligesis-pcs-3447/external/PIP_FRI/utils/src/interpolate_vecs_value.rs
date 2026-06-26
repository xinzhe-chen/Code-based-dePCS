use crate::helper::{nearest_power_of_two, Helper, MultilinearPolynomial};
use crate::merkle_tree::{Blake3Algorithm, MERKLE_ROOT_SIZE};
use crate::merkle_tree::{MerkleTreeProver, MerkleTreeVerifier};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rs_merkle::MerkleTree;
use std::collections::HashMap;

pub fn get_poly_num<T: PrimeField>(poly: &MultilinearPolynomial<T>) -> usize {
    nearest_power_of_two(poly.variable_num() * 4)
    // nearest_power_of_two(18 * 4) * (1 << (poly.variable_num() - 18))
}

// for comparison with Orion, we set poly_num directly nearest_power_of_two
// we currently only use non-zk version as Orion
pub fn get_sub_variable_num<T: PrimeField>(poly: &MultilinearPolynomial<T>) -> usize {
    let poly_num = get_poly_num(poly);
    (poly.coefficients().len() / poly_num).ilog2() as usize
}

pub fn get_tensor<T: PrimeField>(x: &Vec<T>) -> Vec<T> {
    let mut ret = vec![T::ONE];
    x.iter().for_each(|&x| {
        let mut session: Vec<T> = ret.iter().map(|e| *e * x).collect();
        ret.append(&mut session);
    });
    ret
}

#[derive(Clone)]
pub struct InterpolateVecsValue<T: PrimeField> {
    pub values: Vec<Vec<T>>,
    merkle_tree: MerkleTreeProver,
}

// put multiple vectors into one Merkle tree
impl<T: PrimeField> InterpolateVecsValue<T> {
    pub fn new(values: Vec<Vec<T>>) -> Self {
        let len = values[0].len() / 2;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    let mut vec_left = vec![];
                    let mut vec_right = vec![];
                    for j in 0..values.len() {
                        vec_left.push(values[j][i]);
                        vec_right.push(values[j][i + len]);
                    }
                    let vec = [vec_left, vec_right].concat();
                    Helper::to_bytes_vec(&vec)
                })
                .collect(),
        );
        Self {
            values,
            merkle_tree,
        }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn query(&self, leaf_indices: &Vec<usize>) -> QueryVecsResult<T> {
        let len = self.merkle_tree.leave_num();
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j| {
                let mut vec_left = vec![];
                let mut vec_right = vec![];
                for i in 0..self.values.len() {
                    vec_left.push(self.values[i][*j]);
                    vec_right.push(self.values[i][*j + len]);
                }
                [(*j, vec_left), (*j + len, vec_right)]
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryVecsResult {
            proof_bytes,
            proof_values,
            vecs_length: self.values.len(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct QueryVecsResult<T: PrimeField> {
    pub proof_bytes: Vec<u8>,
    pub proof_values: HashMap<usize, Vec<T>>,
    pub vecs_length: usize,
}

impl<T: PrimeField> QueryVecsResult<T> {
    pub fn new() -> Self {
        let proof_bytes: Vec<u8> = Vec::new();
        let proof_values: HashMap<usize, Vec<T>> = HashMap::new();
        let vecs_length: usize = 0;

        QueryVecsResult {
            proof_bytes,
            proof_values,
            vecs_length,
        }
    }

    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let leaves: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|x| {
                Helper::<T>::to_bytes_vec(
                    &[
                        self.proof_values.get(x).unwrap().clone(),
                        self.proof_values
                            .get(&(x + merkle_verifier.leave_number))
                            .unwrap()
                            .clone(),
                    ]
                    .concat(),
                )
            })
            .collect();
        let res = merkle_verifier.verify(self.proof_bytes.clone(), leaf_indices, &leaves);
        assert!(res);
        res
    }

    pub fn combine_proof_values(
        query_vecs: &Vec<QueryVecsResult<T>>,
        sub_vec_size: usize,
    ) -> HashMap<usize, Vec<T>> {
        let n = query_vecs.len(); // 4
        let vec_size = n * sub_vec_size; // 8192
        let sub_tree_size = sub_vec_size / 2; // 1024
        let tree_size = vec_size / 2; // 4096
        let mut merged_map: HashMap<usize, Vec<T>> = HashMap::new();

        for (i, query) in query_vecs.iter().enumerate() {
            for (&key, value) in &query.proof_values {
                let mut new_key = 0;
                if key < sub_tree_size {
                    new_key = key + i * sub_tree_size;
                } else if key >= sub_tree_size {
                    new_key = key - sub_tree_size + i * sub_tree_size + tree_size;
                }
                // println!("new_key: {}", new_key);
                merged_map.insert(new_key, value.clone());
            }
        }

        assert_eq!(
            query_vecs
                .iter()
                .map(|q| q.proof_values.len())
                .sum::<usize>(),
            merged_map.len()
        );

        merged_map
    }

    pub fn combine_proof_bytes(
        query_vecs_results: &Vec<QueryVecsResult<T>>,
        sub_tree_layer_size: &Vec<Vec<usize>>,
        sub_tree_roots: &Vec<[u8; 32]>,
        open_indices: Vec<usize>,
    ) -> Vec<u8> {
        let mut result = Vec::new();
        let n = query_vecs_results.len();
        let m = sub_tree_layer_size[0].len();

        let mut start = vec![0; n];
        let mut end = vec![0; n];
        for j in 0..m {
            for i in 0..n {
                end[i] = start[i] + sub_tree_layer_size[i][j] * MERKLE_ROOT_SIZE;
                result.extend_from_slice(&query_vecs_results[i].proof_bytes[start[i]..end[i]]);
                start[i] = end[i];
            }
        }

        let merkle_tree = MerkleTree::<Blake3Algorithm>::from_leaves(sub_tree_roots);
        let proof_bytes = merkle_tree.proof(&open_indices).to_bytes();
        // println!("proof_bytes len: {:?}", proof_bytes.len() / 32);
        // println!("open_indices: {:?}", open_indices);
        result.extend_from_slice(&proof_bytes[..]);

        assert_eq!(
            query_vecs_results
                .iter()
                .map(|q| q.proof_bytes.len())
                .sum::<usize>()
                + proof_bytes.len(),
            result.len()
        );

        result
    }

    pub fn path_proof_size(&self) -> usize {
        self.proof_bytes.len()
    }

    pub fn field_proof_size(&self) -> usize {
        self.proof_values.len() * self.vecs_length * size_of::<T>()
    }

    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len() + self.proof_values.len() * self.vecs_length * size_of::<T>()
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct QueryVecsResultTest<T: PrimeField> {
    pub proof_bytes: Vec<u8>,
    pub proof_values_k: Vec<usize>,
    pub proof_values_v: Vec<Vec<T>>,
    pub vecs_length: usize,
}

impl<T: PrimeField> QueryVecsResultTest<T> {
    pub fn from_query_vecs_result(query_vecs_result: &QueryVecsResult<T>) -> Self {
        let mut keys = Vec::new();
        let mut values = Vec::new();

        for (key, vec) in &query_vecs_result.proof_values {
            keys.push(*key);
            values.push(vec.clone());
        }

        QueryVecsResultTest {
            proof_bytes: query_vecs_result.proof_bytes.clone(),
            proof_values_k: keys,
            proof_values_v: values,
            vecs_length: query_vecs_result.vecs_length,
        }
    }

    pub fn to_query_vecs_result(&self) -> QueryVecsResult<T> {
        let mut proof_values = HashMap::new();

        for (key, value) in self.proof_values_k.iter().zip(self.proof_values_v.iter()) {
            proof_values.insert(*key, value.clone());
        }

        QueryVecsResult {
            proof_bytes: self.proof_bytes.clone(),
            proof_values,
            vecs_length: self.vecs_length,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::goldilocks::Goldilocks as T;
    use crate::helper::MultilinearPolynomial;
    use crate::interpolate_vecs_value::*;
    use crate::merkle_tree::MerkleTreeVerifier;
    use ark_ff::{Field, UniformRand};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // test for split polynomials and evaluations
    #[test]
    fn test_poly_split() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let poly = MultilinearPolynomial::<T>::rand(6);
        let open_point: Vec<T> = (0..6).into_iter().map(|_| T::rand(&mut rng)).collect();
        let poly_eval = poly.evaluate(&open_point);

        let sub_poly_num = get_poly_num(&poly);
        let sub_polys = poly.chunks(sub_poly_num);
        let sub_poly_var_num = get_sub_variable_num(&poly);
        let (sub_poly_point, remaining_var) = open_point.split_at(sub_poly_var_num);

        // w_1, w_2, ...,
        let remaining_tensor = get_tensor(&remaining_var.to_vec());

        let eval_from_sub_polys = sub_polys
            .iter()
            .zip(remaining_tensor.iter())
            .fold(T::ZERO, |acc, (sub_poly, &w_i)| {
                acc + sub_poly.evaluate(&sub_poly_point.to_vec()) * w_i
            });

        assert_eq!(poly_eval, eval_from_sub_polys);
    }

    #[test]
    fn test_multiple_merkle() {
        let vec_1 = vec![T::from(1), T::from(2), T::from(3), T::from(4)];
        let vec_2 = vec![T::from(5), T::from(6), T::from(7), T::from(8)];
        let values = vec![vec_1, vec_2];
        let leave_number = values[0].len() / 2;

        let interpolation = InterpolateVecsValue::new(values);
        let root = interpolation.commit();
        let leaf_indices = vec![1];
        let query_result = interpolation.query(&leaf_indices);

        println!("proof_values are {:?}", query_result.proof_values);
        println!("proof_values[1] are {:?}", query_result.proof_values[&1]);

        let verifier = MerkleTreeVerifier::new(leave_number, &root);
        let is_valid = query_result.verify_merkle_tree(&leaf_indices, &verifier);
        assert!(is_valid);
    }

    #[test]
    fn test_transformation() {
        let vec_1 = vec![T::from(1), T::from(2), T::from(3), T::from(4)];
        let vec_2 = vec![T::from(5), T::from(6), T::from(7), T::from(8)];
        let values = vec![vec_1, vec_2];
        let _leave_number = values[0].len() / 2;

        let interpolation = InterpolateVecsValue::new(values);
        let _root = interpolation.commit();
        let leaf_indices = vec![1];
        let query_result = interpolation.query(&leaf_indices);

        let a = QueryVecsResultTest::from_query_vecs_result(&query_result);
        let _b = QueryVecsResultTest::to_query_vecs_result(&a);
        // assert_eq!(query_result, b);
    }
}
