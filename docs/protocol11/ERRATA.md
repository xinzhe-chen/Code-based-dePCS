# protocol11 errata and normalization

The implementation resolves the paper's notational inconsistencies as follows.

- Encoded rows and `E1/E2` have length `cN/B`, not `N/B`.
- Per-worker encoded matrices have shape `b x cN/B`.
- Per-worker column-hash vectors have length `cN/B`.
- Protocol 11 local row references use `M_f^(i)[k]`, with `k in [b]`.
- Aggregations over a worker's local rows use `[b]`; global row aggregations
  use `[B]`.
- `s1` addresses the `B` row axis and `s2` addresses the `N/B` column axis.
- The exact equality `B=M log2(N/M)` is padded to the nearest power-of-two
  local row count: `b=next_power_of_two(log2(N/M))`, `B=M*b`. This preserves
  the stated asymptotic complexity and makes every MLE axis well-defined.
- `ell` (column queries) and the DeepFold PCS query count are separate values.
- The concrete PCS backend is DeepFold for every opening, including `H_u`;
  there is no mixed BaseFold/DeepFold execution path.
- `Paper100` means classical-ROM security over `Ft255`. It uses DeepFold's
  unique-decoding radius; the conjectural list-decoding query count is not used.
