use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    EmptyEvaluations,
    NonPowerOfTwo {
        len: usize,
    },
    PointLength {
        expected: usize,
        actual: usize,
    },
    VectorLength {
        expected: usize,
        actual: usize,
    },
    MatrixShapeMismatch {
        left_rows: usize,
        left_cols: usize,
        right_rows: usize,
        right_cols: usize,
    },
    IndexOutOfBounds {
        row: usize,
        col: usize,
        rows: usize,
        cols: usize,
    },
    DivisionByZero,
    InvalidPartition {
        reason: String,
    },
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl Display for CoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEvaluations => write!(f, "evaluation vector must not be empty"),
            Self::NonPowerOfTwo { len } => {
                write!(f, "evaluation vector length {len} is not a power of two")
            }
            Self::PointLength { expected, actual } => {
                write!(
                    f,
                    "point length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::VectorLength { expected, actual } => {
                write!(
                    f,
                    "vector length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MatrixShapeMismatch {
                left_rows,
                left_cols,
                right_rows,
                right_cols,
            } => write!(
                f,
                "matrix shape mismatch: left is {left_rows}x{left_cols}, right is {right_rows}x{right_cols}"
            ),
            Self::IndexOutOfBounds {
                row,
                col,
                rows,
                cols,
            } => write!(
                f,
                "matrix index ({row}, {col}) is outside shape {rows}x{cols}"
            ),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::InvalidPartition { reason } => write!(f, "invalid partition plan: {reason}"),
        }
    }
}

impl Error for CoreError {}
