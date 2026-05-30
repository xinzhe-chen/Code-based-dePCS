use crate::{CoreError, FieldElement, Result, SparseMatrix};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1CS {
    a: SparseMatrix,
    b: SparseMatrix,
    c: SparseMatrix,
}

impl R1CS {
    pub fn new(a: SparseMatrix, b: SparseMatrix, c: SparseMatrix) -> Result<Self> {
        same_shape(&a, &b)?;
        same_shape(&a, &c)?;
        Ok(Self { a, b, c })
    }

    pub fn a(&self) -> &SparseMatrix {
        &self.a
    }

    pub fn b(&self) -> &SparseMatrix {
        &self.b
    }

    pub fn c(&self) -> &SparseMatrix {
        &self.c
    }

    pub fn num_constraints(&self) -> usize {
        self.a.rows()
    }

    pub fn num_variables(&self) -> usize {
        self.a.cols()
    }

    pub fn constraint_values(
        &self,
        witness: &[FieldElement],
    ) -> Result<Vec<(FieldElement, FieldElement, FieldElement)>> {
        let az = self.a.mul_vec(witness)?;
        let bz = self.b.mul_vec(witness)?;
        let cz = self.c.mul_vec(witness)?;
        Ok(az
            .into_iter()
            .zip(bz)
            .zip(cz)
            .map(|((a, b), c)| (a, b, c))
            .collect())
    }

    pub fn is_satisfied(&self, witness: &[FieldElement]) -> Result<bool> {
        Ok(self
            .constraint_values(witness)?
            .into_iter()
            .all(|(a, b, c)| a * b == c))
    }
}

fn same_shape(left: &SparseMatrix, right: &SparseMatrix) -> Result<()> {
    if left.rows() == right.rows() && left.cols() == right.cols() {
        Ok(())
    } else {
        Err(CoreError::MatrixShapeMismatch {
            left_rows: left.rows(),
            left_cols: left.cols(),
            right_rows: right.rows(),
            right_cols: right.cols(),
        })
    }
}
