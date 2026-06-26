use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem::take;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use super::DeNet;

pub trait DeSerNet: DeNet {
    #[inline]
    fn send_to_master<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Option<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_uncompressed(&mut bytes_out).unwrap();
        Self::send_bytes_to_master(bytes_out).map(|bytes_in| {
            bytes_in
                .into_iter()
                .map(|b| T::deserialize_uncompressed_unchecked(&b[..]).unwrap())
                .collect()
        })
    }

    #[inline]
    fn recv_from_master<T: CanonicalDeserialize + CanonicalSerialize + Default>(out: Option<Vec<T>>) -> T {
        if Self::am_master() {
           let bytes = out.as_ref().unwrap()
                .par_iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_uncompressed(&mut bytes_out).unwrap();
                    bytes_out
                })
                .collect();
            Self::recv_bytes_from_master(Some(bytes));
            take(&mut out.unwrap()[Self::party_id()])
        } else {
            let bytes = Self::recv_bytes_from_master(None);
            T::deserialize_uncompressed_unchecked(&bytes[..]).unwrap()
        }
    }

    #[inline]
    fn recv_from_master_uniform<T: CanonicalDeserialize + CanonicalSerialize + Default>(out: Option<T>) -> T {
        if Self::am_master() {
            let mut bytes_out = Vec::new();
            out.as_ref().unwrap().serialize_uncompressed(&mut bytes_out).unwrap();
            Self::recv_bytes_from_master_uniform(Some(bytes_out));
            out.unwrap()
        } else {
            let bytes = Self::recv_bytes_from_master_uniform(None);
            T::deserialize_uncompressed_unchecked(&bytes[..]).unwrap()
        }
    }

}

impl<N: DeNet> DeSerNet for N {}
