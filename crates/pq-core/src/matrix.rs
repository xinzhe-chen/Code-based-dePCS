use crate::{CoreError, FieldElement, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SparseEntry {
    pub row: usize,
    pub col: usize,
    pub value: FieldElement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrix {
    rows: usize,
    cols: usize,
    entries: Vec<SparseEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecomputedSparseMatrix {
    rows: usize,
    cols: usize,
    unit_pos: Vec<Vec<usize>>,
    unit_neg: Vec<Vec<usize>>,
    small: Vec<Vec<(usize, i8)>>,
    general: Vec<Vec<(usize, FieldElement)>>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PrecomputedSparseStats {
    pub unit_pos: usize,
    pub unit_neg: usize,
    pub small: usize,
    pub general: usize,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: Vec::new(),
        }
    }

    pub fn from_entries(rows: usize, cols: usize, entries: Vec<SparseEntry>) -> Result<Self> {
        let matrix = Self {
            rows,
            cols,
            entries,
        };
        matrix.validate_entries()?;
        Ok(matrix)
    }

    pub fn from_dense(rows: &[Vec<FieldElement>]) -> Result<Self> {
        let row_count = rows.len();
        let col_count = rows.first().map_or(0, Vec::len);
        let mut entries = Vec::new();

        for (row, values) in rows.iter().enumerate() {
            if values.len() != col_count {
                return Err(CoreError::VectorLength {
                    expected: col_count,
                    actual: values.len(),
                });
            }
            for (col, value) in values.iter().enumerate() {
                if !value.is_zero() {
                    entries.push(SparseEntry {
                        row,
                        col,
                        value: *value,
                    });
                }
            }
        }

        Ok(Self {
            rows: row_count,
            cols: col_count,
            entries,
        })
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn nnz(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[SparseEntry] {
        &self.entries
    }

    pub fn add_entry(&mut self, row: usize, col: usize, value: FieldElement) -> Result<()> {
        if row >= self.rows || col >= self.cols {
            return Err(CoreError::IndexOutOfBounds {
                row,
                col,
                rows: self.rows,
                cols: self.cols,
            });
        }
        if !value.is_zero() {
            self.entries.push(SparseEntry { row, col, value });
        }
        Ok(())
    }

    pub fn row_dot(&self, row: usize, vector: &[FieldElement]) -> Result<FieldElement> {
        if vector.len() != self.cols {
            return Err(CoreError::VectorLength {
                expected: self.cols,
                actual: vector.len(),
            });
        }
        if row >= self.rows {
            return Err(CoreError::IndexOutOfBounds {
                row,
                col: 0,
                rows: self.rows,
                cols: self.cols,
            });
        }

        Ok(self
            .entries
            .iter()
            .filter(|entry| entry.row == row)
            .map(|entry| entry.value * vector[entry.col])
            .sum())
    }

    pub fn mul_vec(&self, vector: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.precompute().mul_vec(vector)
    }

    pub fn mul_vec_naive(&self, vector: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.validate_vector_len(vector)?;
        Ok(self.mul_vec_naive_unchecked(vector))
    }

    pub fn precompute(&self) -> PrecomputedSparseMatrix {
        PrecomputedSparseMatrix::from_sparse(self)
    }

    fn mul_vec_naive_unchecked(&self, vector: &[FieldElement]) -> Vec<FieldElement> {
        let mut out = vec![FieldElement::ZERO; self.rows];
        for entry in &self.entries {
            out[entry.row] += entry.value * vector[entry.col];
        }
        out
    }

    fn validate_vector_len(&self, vector: &[FieldElement]) -> Result<()> {
        if vector.len() == self.cols {
            Ok(())
        } else {
            Err(CoreError::VectorLength {
                expected: self.cols,
                actual: vector.len(),
            })
        }
    }

    fn validate_entries(&self) -> Result<()> {
        for entry in &self.entries {
            if entry.row >= self.rows || entry.col >= self.cols {
                return Err(CoreError::IndexOutOfBounds {
                    row: entry.row,
                    col: entry.col,
                    rows: self.rows,
                    cols: self.cols,
                });
            }
        }
        Ok(())
    }
}

impl PrecomputedSparseMatrix {
    /// Precomputes row buckets following Spartan2's sparse-matrix accelerator:
    /// unit coefficients, small signed coefficients, and general field values.
    ///
    /// Source reference: `third_party/Spartan2/src/r1cs/sparse.rs`,
    /// `PrecomputedSparseMatrix::from_sparse`.
    pub fn from_sparse(matrix: &SparseMatrix) -> Self {
        let mut unit_pos = vec![Vec::new(); matrix.rows];
        let mut unit_neg = vec![Vec::new(); matrix.rows];
        let mut small = vec![Vec::new(); matrix.rows];
        let mut general = vec![Vec::new(); matrix.rows];

        for entry in matrix.entries() {
            if entry.value == FieldElement::ONE {
                unit_pos[entry.row].push(entry.col);
            } else if entry.value == -FieldElement::ONE {
                unit_neg[entry.row].push(entry.col);
            } else if let Some(coeff) = signed_small_coeff(entry.value) {
                small[entry.row].push((entry.col, coeff));
            } else {
                general[entry.row].push((entry.col, entry.value));
            }
        }

        Self {
            rows: matrix.rows,
            cols: matrix.cols,
            unit_pos,
            unit_neg,
            small,
            general,
        }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn stats(&self) -> PrecomputedSparseStats {
        PrecomputedSparseStats {
            unit_pos: self.unit_pos.iter().map(Vec::len).sum(),
            unit_neg: self.unit_neg.iter().map(Vec::len).sum(),
            small: self.small.iter().map(Vec::len).sum(),
            general: self.general.iter().map(Vec::len).sum(),
        }
    }

    pub fn mul_vec(&self, vector: &[FieldElement]) -> Result<Vec<FieldElement>> {
        self.validate_vector_len(vector)?;
        let mut out = Vec::with_capacity(self.rows);
        for row in 0..self.rows {
            out.push(self.compute_row(row, vector));
        }
        Ok(out)
    }

    pub fn row_dot(&self, row: usize, vector: &[FieldElement]) -> Result<FieldElement> {
        self.validate_vector_len(vector)?;
        if row >= self.rows {
            return Err(CoreError::IndexOutOfBounds {
                row,
                col: 0,
                rows: self.rows,
                cols: self.cols,
            });
        }
        Ok(self.compute_row(row, vector))
    }

    fn compute_row(&self, row: usize, vector: &[FieldElement]) -> FieldElement {
        let mut sum = FieldElement::ZERO;
        for col in &self.unit_pos[row] {
            sum += vector[*col];
        }
        for col in &self.unit_neg[row] {
            sum -= vector[*col];
        }
        for (col, coeff) in &self.small[row] {
            sum += small_mul(*coeff, vector[*col]);
        }
        for (col, value) in &self.general[row] {
            sum += *value * vector[*col];
        }
        sum
    }

    fn validate_vector_len(&self, vector: &[FieldElement]) -> Result<()> {
        if vector.len() == self.cols {
            Ok(())
        } else {
            Err(CoreError::VectorLength {
                expected: self.cols,
                actual: vector.len(),
            })
        }
    }
}

fn signed_small_coeff(value: FieldElement) -> Option<i8> {
    for coeff in 2_i8..=7 {
        let field = FieldElement::from(coeff as u64);
        if value == field {
            return Some(coeff);
        }
        if value == -field {
            return Some(-coeff);
        }
    }
    None
}

fn small_mul(coeff: i8, value: FieldElement) -> FieldElement {
    let abs = coeff.unsigned_abs();
    let result = match abs {
        2 => value + value,
        3 => value + value + value,
        4 => {
            let double = value + value;
            double + double
        }
        5 => {
            let double = value + value;
            double + double + value
        }
        6 => {
            let double = value + value;
            double + double + double
        }
        7 => {
            let double = value + value;
            double + double + double + value
        }
        _ => unreachable!("small coefficient classification only stores 2..=7"),
    };
    if coeff < 0 { -result } else { result }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(value: u64) -> FieldElement {
        FieldElement::from(value)
    }

    #[test]
    fn precomputed_sparse_matrix_matches_naive_multiplication() {
        let mut matrix = SparseMatrix::new(3, 5);
        matrix.add_entry(0, 0, FieldElement::ONE).expect("entry");
        matrix.add_entry(0, 1, -FieldElement::ONE).expect("entry");
        matrix.add_entry(0, 2, fe(3)).expect("entry");
        matrix.add_entry(1, 1, -fe(7)).expect("entry");
        matrix.add_entry(1, 3, fe(9)).expect("entry");
        matrix.add_entry(2, 4, fe(2)).expect("entry");

        let vector = vec![fe(2), fe(3), fe(5), fe(7), fe(11)];
        let precomputed = matrix.precompute();

        assert_eq!(
            precomputed.mul_vec(&vector).expect("precomputed"),
            matrix.mul_vec_naive(&vector).expect("naive")
        );
        assert_eq!(
            precomputed.row_dot(1, &vector).expect("row"),
            matrix.row_dot(1, &vector).expect("row naive")
        );
    }

    #[test]
    fn precomputed_sparse_matrix_classifies_spartan_coefficient_buckets() {
        let mut matrix = SparseMatrix::new(1, 5);
        matrix.add_entry(0, 0, FieldElement::ONE).expect("entry");
        matrix.add_entry(0, 1, -FieldElement::ONE).expect("entry");
        matrix.add_entry(0, 2, fe(2)).expect("entry");
        matrix.add_entry(0, 3, -fe(7)).expect("entry");
        matrix.add_entry(0, 4, fe(11)).expect("entry");

        let stats = matrix.precompute().stats();
        assert_eq!(
            stats,
            PrecomputedSparseStats {
                unit_pos: 1,
                unit_neg: 1,
                small: 2,
                general: 1,
            }
        );
    }
}
