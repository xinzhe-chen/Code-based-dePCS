use super::{field::MyField, polynomial::Polynomial};
use crate::batch_bit_reverse;

#[derive(Debug, Clone, Copy)]
struct Radix2Domain<T: MyField> {
    order: usize,
    omega: T,
}

impl<T: MyField> Radix2Domain<T> {
    #[inline]
    pub fn new(order: usize, omega: T) -> Self {
        Radix2Domain { order, omega }
    }

    #[inline]
    pub fn order(&self) -> usize {
        self.order
    }

    #[inline]
    pub fn omega(&self) -> T {
        self.omega
    }

    #[inline]
    pub fn fft(&self, a: &mut Vec<T>) {
        _fft(a, self.omega);
    }

    #[inline]
    pub fn ifft(&self, a: &mut Vec<T>) {
        _fft(a, self.omega.inverse());
        let t = T::from_int(self.order as u64).inverse();
        for i in a {
            *i *= t;
        }
    }

    #[inline]
    pub fn coset_fft(&self, a: &mut Vec<T>, shift: T) {
        multiply_by_coset(a, shift);
        self.fft(a);
    }

    #[inline]
    pub fn coset_ifft(&self, a: &mut Vec<T>, shift: T) {
        self.ifft(a);
        multiply_by_coset(a, shift.inverse());
    }
}

fn multiply_by_coset<T: MyField>(a: &mut Vec<T>, shift: T) {
    let mut t = shift;
    for i in 1..a.len() {
        a[i] *= t;
        t *= shift;
    }
}

fn _fft<T: MyField>(a: &mut Vec<T>, omega: T) {
    let n = a.len();
    let log_n = n.ilog2() as usize;
    let rank = batch_bit_reverse(log_n);
    for i in 0..n {
        if i < rank[i] {
            (a[i], a[rank[i]]) = (a[rank[i]], a[i]);
        }
    }
    let mut log_m = 0usize;
    for _i in 0..log_n {
        let w_m = omega.pow(n >> (log_m + 1));
        let m = 1 << log_m;
        for j in (0..n).step_by(m * 2) {
            let mut w = T::from_int(1);
            for k in 0..m {
                let t = w * a[j + k + m];
                a[j + k + m] = a[j + k] - t;
                a[j + k] += t;
                w *= w_m;
            }
        }
        log_m += 1;
    }
}

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Coset<T: MyField> {
    elements: Arc<Vec<T>>,
    elements_inv: Arc<Vec<T>>,
    fft_eval_domain: Radix2Domain<T>,
    shift: T,
}

impl<T: MyField> Coset<T> {
    pub fn mult(poly1: &Polynomial<T>, poly2: &Polynomial<T>) -> Polynomial<T> {
        let degree = {
            let max_d = std::cmp::max(poly1.degree(), poly2.degree()) + 1;
            let mut d = 1;
            while d < max_d {
                d <<= 1;
            }
            d << 1
        };
        let domain = Radix2Domain::new(degree, T::get_generator(degree));
        let mut coeff1 = poly1.coefficients().clone();
        let len = coeff1.len();
        coeff1.append(&mut (len..degree).into_iter().map(|_| T::from_int(0)).collect());
        let mut coeff2 = poly2.coefficients().clone();
        let len = coeff2.len();
        coeff2.append(&mut (len..degree).into_iter().map(|_| T::from_int(0)).collect());
        domain.fft(&mut coeff1);
        domain.fft(&mut coeff2);
        for i in 0..degree {
            coeff1[i] *= coeff2[i];
        }
        domain.ifft(&mut coeff1);
        let poly = Polynomial::new(coeff1);
        poly
    }

    pub fn new(order: usize, shift: T) -> Self {
        assert!(!shift.is_zero());
        let omega = T::get_generator(order);
        let elements = std::iter::successors(Some(shift), |&last| Some(last * omega))
            .take(order)
            .collect();
        let omega_inv = omega.pow(order - 1);
        let elements_inv = std::iter::successors(Some(shift), |&last| Some(last * omega_inv))
            .take(order)
            .collect();
        Coset {
            elements: Arc::new(elements),
            elements_inv: Arc::new(elements_inv),
            fft_eval_domain: Radix2Domain::new(order, omega),
            shift,
        }
    }

    /// Construct a coset without materializing its element/inverse tables.
    /// `element_at`/`element_inv_at` then compute points lazily as powers of the
    /// domain generator. Use this on the verifier side, where only O(query*log)
    /// points are ever read and the full O(order) tables are pure overhead.
    /// The prover must keep using `new`, since folding scans the whole table.
    pub fn new_lazy(order: usize, shift: T) -> Self {
        assert!(!shift.is_zero());
        let omega = T::get_generator(order);
        Coset {
            elements: Arc::new(Vec::new()),
            elements_inv: Arc::new(Vec::new()),
            fft_eval_domain: Radix2Domain::new(order, omega),
            shift,
        }
    }

    pub fn order(&self) -> usize {
        self.fft_eval_domain.order
    }

    pub fn pow(&self, index: usize) -> Coset<T> {
        assert_eq!(index & (index - 1), 0);
        let lowbit = (index as i64 & (-(index as i64))) as usize;
        Coset::new(self.order() / lowbit, self.shift.pow(index))
    }

    /// Lazy analogue of `pow`: derive the squared/strided coset without building
    /// its element tables, so a chain of lazy cosets stays allocation-free.
    pub fn pow_lazy(&self, index: usize) -> Coset<T> {
        assert_eq!(index & (index - 1), 0);
        let lowbit = (index as i64 & (-(index as i64))) as usize;
        Coset::new_lazy(self.order() / lowbit, self.shift.pow(index))
    }

    pub fn generator(&self) -> T {
        self.fft_eval_domain.omega
    }

    pub fn element_at(&self, index: usize) -> T {
        // Lazy cosets (built via `new_lazy`) carry no materialized element table;
        // compute `shift * omega^index` on demand so a verifier that only reads
        // O(query * log) sampled points never allocates the full O(domain) vector.
        if self.elements.is_empty() {
            self.shift * self.fft_eval_domain.omega.pow(index)
        } else {
            self.elements[index]
        }
    }

    pub fn element_inv_at(&self, index: usize) -> T {
        if self.elements_inv.is_empty() {
            // Materialized `elements_inv[i] = shift * omega^(-i)`; recover the
            // inverse exponent modulo the domain order with a single field pow.
            let order = self.fft_eval_domain.order;
            let exp = (order - index % order) % order;
            self.shift * self.fft_eval_domain.omega.pow(exp)
        } else {
            self.elements_inv[index]
        }
    }

    pub fn all_elements_inv(&self) -> Vec<T> {
        (*self.elements_inv).clone()
    }

    pub fn all_elements(&self) -> Vec<T> {
        (*self.elements).clone()
    }

    pub fn size(&self) -> usize {
        self.fft_eval_domain.order()
    }

    pub fn fft(&self, mut coeff: Vec<T>) -> Vec<T> {
        let n = self.size() - coeff.len();
        for _i in 0..n {
            coeff.push(T::from_int(0));
        }
        self.fft_eval_domain.coset_fft(&mut coeff, self.shift);
        coeff
    }

    pub fn ifft(&self, mut evals: Vec<T>) -> Vec<T> {
        if evals.len() == 1 {
            return vec![evals[0]];
        };
        assert_eq!(self.size(), evals.len());
        self.fft_eval_domain.coset_ifft(&mut evals, self.shift);
        evals
    }

    pub fn shift(&self) -> T {
        self.shift
    }
}

#[cfg(test)]
mod tests {
    use crate::algebra::field::{ft255::Ft255, mersenne61_ext::Mersenne61Ext};

    use super::*;

    #[test]
    fn fft_and_ifft() {
        let mut a = vec![];
        let mut b = vec![];
        for _i in 0..16 {
            a.push(Ft255::random_element());
            b.push(Ft255::random_element());
        }
        let fft_a_times_b = Coset::mult(&Polynomial::new(a.clone()), &Polynomial::new(b.clone()));
        for _i in 16..32 {
            a.push(Ft255::from_int(0));
            b.push(Ft255::from_int(0));
        }
        let mut a_times_b = vec![];
        for _i in 0..32 {
            a_times_b.push(Ft255::from_int(0));
        }
        for i in 0..16usize {
            for j in 0..16usize {
                a_times_b[i + j] += a[i] * b[j];
            }
        }
        while a_times_b.last().unwrap().is_zero() {
            a_times_b.pop();
        }
        assert_eq!(fft_a_times_b.coefficients().clone(), a_times_b);
        let coset = Coset::new(32, Ft255::random_element());
        let b = coset.fft(a.clone());
        let c = coset.ifft(b);
        assert_eq!(a, c);
    }

    #[test]
    fn all_elements() {
        let r = Ft255::random_element();
        let coset = Coset::new(32, r);
        let elements = coset.all_elements();
        assert_eq!(elements[0], r);
        let omega = coset.fft_eval_domain.omega();
        for i in 0..elements.len() - 1 {
            assert_eq!(elements[i] * omega, elements[i + 1]);
        }
        assert_eq!(*elements.last().unwrap() * omega, elements[0]);
    }

    #[test]
    fn pow() {
        let shift = Mersenne61Ext::random_element();
        let coset = Coset::new(32, shift);
        let coset_square = coset.pow(2);
        for (idx, i) in coset_square.all_elements().iter().enumerate() {
            assert_eq!(*i, coset.all_elements()[idx].pow(2));
            assert_eq!(*i, coset.all_elements()[idx + coset_square.size()].pow(2));
        }
    }
}
