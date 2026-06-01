use crate::{CoreError, FieldElement, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gate {
    Add {
        left: usize,
        right: usize,
        out: usize,
    },
    Mul {
        left: usize,
        right: usize,
        out: usize,
    },
    Const {
        wire: usize,
        value: FieldElement,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlonkishRow {
    pub a: FieldElement,
    pub b: FieldElement,
    pub c: FieldElement,
    pub q_l: FieldElement,
    pub q_r: FieldElement,
    pub q_o: FieldElement,
    pub q_m: FieldElement,
    pub q_c: FieldElement,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomizedGate {
    monomials: Vec<GateMonomial>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateMonomial {
    pub coeff: i64,
    pub selector: Option<usize>,
    pub witnesses: Vec<usize>,
}

impl PlonkishRow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        a: FieldElement,
        b: FieldElement,
        c: FieldElement,
        q_l: FieldElement,
        q_r: FieldElement,
        q_o: FieldElement,
        q_m: FieldElement,
        q_c: FieldElement,
    ) -> Self {
        Self {
            a,
            b,
            c,
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
        }
    }

    pub fn multiplication(a: FieldElement, b: FieldElement, c: FieldElement) -> Self {
        Self::new(
            a,
            b,
            c,
            FieldElement::ZERO,
            FieldElement::ZERO,
            -FieldElement::ONE,
            FieldElement::ONE,
            FieldElement::ZERO,
        )
    }

    pub fn linear(
        a: FieldElement,
        b: FieldElement,
        c: FieldElement,
        q_l: FieldElement,
        q_r: FieldElement,
        q_o: FieldElement,
        q_c: FieldElement,
    ) -> Self {
        Self::new(a, b, c, q_l, q_r, q_o, FieldElement::ZERO, q_c)
    }

    pub fn evaluate(&self) -> FieldElement {
        CustomizedGate::vanilla_plonk_gate().evaluate(&self.selectors(), &self.witnesses())
    }

    pub fn is_satisfied(&self) -> bool {
        self.evaluate().is_zero()
    }

    pub fn selectors(&self) -> [FieldElement; 5] {
        [self.q_l, self.q_r, self.q_o, self.q_m, self.q_c]
    }

    pub fn witnesses(&self) -> [FieldElement; 3] {
        [self.a, self.b, self.c]
    }
}

impl CustomizedGate {
    /// Returns HyperPlonk's vanilla Plonk customized gate:
    /// `q_l*a + q_r*b + q_o*c + q_m*a*b + q_c`.
    ///
    /// Source reference:
    /// `third_party/hyperplonk/hyperplonk/src/custom_gate.rs`,
    /// `CustomizedGates::vanilla_plonk_gate`.
    pub fn vanilla_plonk_gate() -> Self {
        Self {
            monomials: vec![
                GateMonomial {
                    coeff: 1,
                    selector: Some(0),
                    witnesses: vec![0],
                },
                GateMonomial {
                    coeff: 1,
                    selector: Some(1),
                    witnesses: vec![1],
                },
                GateMonomial {
                    coeff: 1,
                    selector: Some(2),
                    witnesses: vec![2],
                },
                GateMonomial {
                    coeff: 1,
                    selector: Some(3),
                    witnesses: vec![0, 1],
                },
                GateMonomial {
                    coeff: 1,
                    selector: Some(4),
                    witnesses: Vec::new(),
                },
            ],
        }
    }

    pub fn monomials(&self) -> &[GateMonomial] {
        &self.monomials
    }

    pub fn degree(&self) -> usize {
        self.monomials
            .iter()
            .map(|monomial| monomial.witnesses.len() + usize::from(monomial.selector.is_some()))
            .max()
            .unwrap_or(0)
    }

    pub fn num_selector_columns(&self) -> usize {
        self.monomials
            .iter()
            .filter(|monomial| monomial.selector.is_some())
            .count()
    }

    pub fn num_witness_columns(&self) -> usize {
        self.monomials
            .iter()
            .flat_map(|monomial| monomial.witnesses.iter().copied())
            .max()
            .map_or(0, |max_index| max_index + 1)
    }

    /// Evaluates a customized gate following HyperPlonk's `eval_f` utility:
    /// each monomial multiplies an integer coefficient, an optional selector,
    /// and the referenced witness values.
    ///
    /// Source reference:
    /// `third_party/hyperplonk/hyperplonk/src/utils.rs::eval_f`.
    pub fn evaluate(
        &self,
        selector_evals: &[FieldElement],
        witness_evals: &[FieldElement],
    ) -> FieldElement {
        let mut out = FieldElement::ZERO;
        for monomial in &self.monomials {
            let mut term = signed_coeff(monomial.coeff);
            if let Some(selector) = monomial.selector {
                term *= selector_evals[selector];
            }
            for witness in &monomial.witnesses {
                term *= witness_evals[*witness];
            }
            out += term;
        }
        out
    }
}

fn signed_coeff(coeff: i64) -> FieldElement {
    if coeff < 0 {
        -FieldElement::from(coeff.unsigned_abs())
    } else {
        FieldElement::from(coeff as u64)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlonkishCircuit {
    rows: Vec<PlonkishRow>,
    num_wires: usize,
    gates: Vec<Gate>,
    permutation: Vec<usize>,
}

impl PlonkishCircuit {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            num_wires: 0,
            gates: Vec::new(),
            permutation: Vec::new(),
        }
    }

    pub fn from_rows(rows: Vec<PlonkishRow>) -> Self {
        Self {
            rows,
            num_wires: 0,
            gates: Vec::new(),
            permutation: Vec::new(),
        }
    }

    pub fn from_gate_permutation(
        num_wires: usize,
        gates: Vec<Gate>,
        permutation: Vec<usize>,
    ) -> Result<Self> {
        for gate in &gates {
            validate_gate_indices(num_wires, gate)?;
        }
        if permutation.len() != num_wires {
            return Err(CoreError::VectorLength {
                expected: num_wires,
                actual: permutation.len(),
            });
        }
        let mut seen = vec![false; num_wires];
        for target in &permutation {
            if *target >= num_wires || seen[*target] {
                return Err(CoreError::InvalidPartition {
                    reason: "permutation must be a bijection over witness indices".to_owned(),
                });
            }
            seen[*target] = true;
        }
        Ok(Self {
            rows: Vec::new(),
            num_wires,
            gates,
            permutation,
        })
    }

    pub fn rows(&self) -> &[PlonkishRow] {
        &self.rows
    }

    pub fn len(&self) -> usize {
        if self.rows.is_empty() {
            self.gates.len()
        } else {
            self.rows.len()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.gates.is_empty()
    }

    pub fn push_row(&mut self, row: PlonkishRow) {
        self.rows.push(row);
    }

    pub fn num_wires(&self) -> usize {
        self.num_wires
    }

    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    pub fn permutation(&self) -> &[usize] {
        &self.permutation
    }

    pub fn row_evaluations(&self) -> Vec<FieldElement> {
        self.rows.iter().map(PlonkishRow::evaluate).collect()
    }

    pub fn is_satisfied(&self) -> bool {
        if !self.gates.is_empty() || !self.permutation.is_empty() {
            return false;
        }
        self.rows.iter().all(PlonkishRow::is_satisfied)
    }

    pub fn is_satisfied_with_witness(&self, witness: &[FieldElement]) -> Result<bool> {
        if witness.len() != self.num_wires {
            return Err(CoreError::VectorLength {
                expected: self.num_wires,
                actual: witness.len(),
            });
        }
        for gate in &self.gates {
            let ok = match *gate {
                Gate::Add { left, right, out } => witness[left] + witness[right] == witness[out],
                Gate::Mul { left, right, out } => witness[left] * witness[right] == witness[out],
                Gate::Const { wire, value } => witness[wire] == value,
            };
            if !ok {
                return Ok(false);
            }
        }
        for (idx, target) in self.permutation.iter().copied().enumerate() {
            if witness[idx] != witness[target] {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn sample_gate_permutation() -> (Self, Vec<FieldElement>) {
        let circuit = Self::from_gate_permutation(
            5,
            vec![
                Gate::Const {
                    wire: 0,
                    value: FieldElement::from(3_u64),
                },
                Gate::Const {
                    wire: 1,
                    value: FieldElement::from(4_u64),
                },
                Gate::Mul {
                    left: 0,
                    right: 1,
                    out: 2,
                },
                Gate::Add {
                    left: 2,
                    right: 1,
                    out: 3,
                },
            ],
            vec![0, 1, 4, 3, 2],
        )
        .expect("sample plonkish");
        let witness = vec![
            FieldElement::from(3_u64),
            FieldElement::from(4_u64),
            FieldElement::from(12_u64),
            FieldElement::from(16_u64),
            FieldElement::from(12_u64),
        ];
        (circuit, witness)
    }
}

fn validate_gate_indices(num_wires: usize, gate: &Gate) -> Result<()> {
    let check = |index: usize| {
        if index >= num_wires {
            return Err(CoreError::IndexOutOfBounds {
                row: 0,
                col: index,
                rows: 1,
                cols: num_wires,
            });
        }
        Ok(())
    };

    match *gate {
        Gate::Add { left, right, out } | Gate::Mul { left, right, out } => {
            check(left)?;
            check(right)?;
            check(out)?;
        }
        Gate::Const { wire, .. } => check(wire)?,
    }
    Ok(())
}
