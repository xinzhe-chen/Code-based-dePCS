# Third-party sources

This repository is scoped to the transparent distributed PCS (dePCS). Two
vendored trees are kept:

- **`deepfold-bench-v0.1/`** — the DeepFold artifact backend. This is
  the only vendored **workspace dependency**: `crates/pq-pcs` depends on its
  `deepfold` and `util` crates by path. Do not move or rename it
  without updating `crates/pq-pcs/Cargo.toml`.
- **`ligesis-pcs-3447/`** — the three distributed-PCS comparison baselines the
  benchmark measures against. It is *not* a workspace dependency;
  `scripts/benchmark.py` builds and runs its example binaries as separate
  processes:
  - **LigeSIS (dLigesis)** — `ligesis-pcs/`
  - **dFRIttata** — `ligesis-pcs/` example, backed by `external/winterfell`
  - **dPIP-FRI** — `external/PIP_FRI`

  Override its location with `benchmark.py --ligesis-dir` if it moves.

Out of scope (removed): KZG/IPA/curve commitments and the earlier PIOP-frontend
reference sources (Spartan2, HyperPlonk). Only transparent hash/Merkle +
Brakedown-style code is on the dePCS path.

## Hygiene

- Do not commit upstream build outputs or benchmark scratch files from vendored
  projects (`target/` and `results/` are git-ignored).
