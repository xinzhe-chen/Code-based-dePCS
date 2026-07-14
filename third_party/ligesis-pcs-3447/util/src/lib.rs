// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Utilities for slice iteration.

/// This function creates a slice iterator.
///
/// # Usage
/// let v = [1, 2, 3, 4, 5];
/// let sum = parallelizable_slice_iter(&v).sum();
pub fn parallelizable_slice_iter<T>(data: &[T]) -> core::slice::Iter<T> {
    data.iter()
}
