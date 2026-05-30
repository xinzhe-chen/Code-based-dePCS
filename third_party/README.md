# Third-Party Source Reuse Plan

The first implementation keeps the protocol code local and dependency-light so
the module boundaries can be tested immediately. External sources are vendored
under `third_party/` and pinned in `PINS.md` before their code is used for
implementation work.

Required fixed sources:

- Spartan / Spartan2: use only R1CS, sumcheck, and PIOP structure as reference.
  Do not reuse Ristretto, IPA, KZG, or any non-PQ commitment layer as the final
  PCS.
- HyperPlonk / HyperPianist: use only Plonkish arithmetization, gate checks,
  permutation checks, and distributed PIOP structure as reference. Do not reuse
  KZG as the final PCS.
- Brakedown / BaseFold: use as the target design for the transparent PCS
  module. Any imported implementation must be pinned to an exact commit.

For any additional vendored source, record:

- upstream URL;
- exact commit;
- license;
- copied paths;
- local changes;
- which protocol pieces are used and which commitment pieces are intentionally
  excluded.
