# Third-Party Pins

These sources are vendored as implementation references. The local prototype
does not reuse curve/KZG/IPA commitments as its final PCS; only PIOP,
arithmetization, and sumcheck structure should be ported from these sources.

## Spartan2

- Upstream: `https://github.com/microsoft/Spartan2.git`
- Local path: `third_party/references/Spartan2`
- Pinned commit: `0d4f1409e8f30536b8b25ed3f81bc446ed717e61`
- License: MIT
- Intended use: R1CS frontend, Spartan-style sumcheck organization, and
  PCS-generic interface design.
- Excluded from final PCS: any non-transparent or non-post-quantum commitment
  backend.
- Current note: upstream README states Spark optimization is not implemented,
  so this project keeps the distributed Spark/Spark-like memory-check logic in
  local code.

## HyperPlonk

- Upstream: `https://github.com/EspressoSystems/hyperplonk.git`
- Local path: `third_party/references/hyperplonk`
- Pinned commit: `2a3b55c97ad8a5d6627108a2e7def2aeccb7f3b9`
- License: MIT
- Intended use: Plonkish arithmetization, gate/permutation PIOP structure, and
  transcript organization.
- Excluded from final PCS: KZG or other non-PQ commitment backends.

