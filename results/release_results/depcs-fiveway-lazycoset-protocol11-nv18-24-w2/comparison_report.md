# dePCS BaseFold vs DeepFold vs External PCS Benchmark Report

- generated_at: 2026-06-27T01:30:22
- depcs_artifact_dirs: `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494788991`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494790363`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494791893`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494793643`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494795942`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494799278`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494804767`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494815500`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494817236`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494819421`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494822626`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494827834`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494837123`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-lazycoset-protocol11-nv18-24-w2\pcs-bench-1782494856375`
- benchmark_design: fair sequential reproduction over nv=18..24; each benchmark row (scheme,nv,workers) runs alone with a per-row timeout, after release binaries are built.
- size_semantics: nv is the number of multilinear polynomial variables; polynomial length is N=2^nv. These are PCS sizes, not circuit gate counts.
- scheduling: strict row order is depcs-deepfold, depcs-basefold, LigeSIS, dFRIttata, dPIP-FRI; within each scheme rows run nv ascending then workers ascending. host_logical_cores=20, max_workers=2, cores_per_worker=10. protocol11 dePCS rows must report master/worker network sent+recv bytes; paper-native rows are PCS-only and external party processes use cores_per_worker threads each.
- timeout_policy: fair rows use per-row timeouts: dePCS=600s, LigeSIS=900s, external=900s; a timeout marks only that row blocked.
- query_count_semantics: dePCS BaseFold/DeepFold use the paper-backed backend query policy; dFRIttata, dPIP-FRI, and LigeSIS use their scheme-native query settings unless `--force-external-query-count` is explicitly set.
- proof_size_semantics: `proof KiB` is the verifier-received PCS commitment object plus PCS opening proof. It is not prover-local committed polynomial storage.
- communication_semantics: `dePCS send+recv KiB` is only master/worker network sent plus received bytes from dePCS protocol11 rows. External and LigeSIS native communication is reported separately as `native comm KiB`; `communication_cost_kib` is a chart-only derived value with `communication_cost_basis`.
- verifier_semantics: paper-backed dePCS uses parallel independent artifact PCS verification plus batched Protocol10/11 consistency checks; no unsupported artifact batch-verify API is assumed.
- batch_boundary: `protocol11-batch` is an explicit experimental runner. If a real artifact-native batch opening cannot be constructed without changing the field/backend semantics, the row is recorded as blocked instead of falling back to individual worker proofs.
- scalability_semantics: worker-local and end-to-end scaling fields are meaningful only for distributed dePCS rows with `communication_basis=master_worker_sent_recv`.
- interpretation: paper-native rows are PCS-only artifact timings and must not be read as distributed dePCS Protocol10/11 evidence.
- local_simulation_caveat: this is a single-machine Rayon simulation, so high worker counts also include scheduler, cache, memory-bandwidth, and proof-object allocation noise.
- implementation_boundary: `--opening protocol11` may not silently fall back to paper-native PCS core. If paper-backed Protocol10/11 is unavailable, the row is blocked instead of emitted as dePCS.
- comparison_chart_filter: blocked rows are omitted from comparison bar charts; dePCS scalability baselines use the smallest requested worker count.
- charts: `comparison_prover_time.svg`, `comparison_verify_time.svg`, `comparison_proof_size.svg`, `comparison_communication.svg`, `depcs_worker_local_compute_scaling.svg`, `depcs_end_to_end_open_proof_scaling.svg`
- raw_table: `comparison_summary.csv` includes `worker_local_compute_ms`, `end_to_end_open_proof_ms`, paper worker commit/open/verify max/sum, master assemble, and scaling fields.

## Result Table

| scheme | backend | rate inv | runner | opening | nv / N | nodes | commit ms | open ms | verify ms | prover ms | proof KiB | dePCS send+recv KiB | native comm KiB | comm basis | verified |
| --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 18 / 262144 | 2 | 71.180 | 65.870 | 6.166 | 137.050 | 452.84 | 447.30 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 19 / 524288 | 2 | 161.979 | 119.446 | 7.108 | 281.425 | 528.18 | 522.29 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 20 / 1048576 | 2 | 305.791 | 211.953 | 8.136 | 517.744 | 616.74 | 610.49 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 21 / 2097152 | 2 | 645.730 | 416.164 | 8.889 | 1061.894 | 704.35 | 697.74 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 22 / 4194304 | 2 | 1294.165 | 786.452 | 9.655 | 2080.618 | 795.23 | 788.26 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 23 / 8388608 | 2 | 2667.271 | 1576.695 | 11.015 | 4243.965 | 895.23 | 887.90 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 24 / 16777216 | 2 | 6181.860 | 3302.261 | 14.165 | 9484.122 | 999.29 | 991.60 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 18 / 262144 | 2 | 309.659 | 173.313 | 8.756 | 482.972 | 704.24 | 699.30 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 19 / 524288 | 2 | 614.319 | 337.712 | 9.703 | 952.031 | 805.05 | 799.76 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 20 / 1048576 | 2 | 1292.524 | 655.273 | 11.185 | 1947.796 | 922.40 | 916.74 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 21 / 2097152 | 2 | 2664.341 | 1300.454 | 11.933 | 3964.795 | 1039.65 | 1033.63 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 22 / 4194304 | 2 | 5371.472 | 2688.293 | 13.766 | 8059.765 | 1157.10 | 1150.73 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 23 / 8388608 | 2 | 11882.432 | 6096.152 | 21.846 | 17978.584 | 1301.23 | 1294.49 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 24 / 16777216 | 2 | 32556.982 | 23407.326 | 19.917 | 55964.308 | 1436.02 | 1428.93 | n/a | master_worker_sent_recv | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 18 / 262144 | 2 | 67.226 | 302.596 | 14.461 | 369.822 | 218.51 | n/a | 28006.40 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 19 / 524288 | 2 | 148.082 | 351.986 | 19.209 | 500.068 | 222.26 | n/a | 38717.44 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 20 / 1048576 | 2 | 213.638 | 586.469 | 27.657 | 800.107 | 241.47 | n/a | 55941.12 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 21 / 2097152 | 2 | 325.358 | 685.239 | 38.458 | 1010.597 | 245.30 | n/a | 77373.44 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 22 / 4194304 | 2 | 493.726 | 1968.901 | 56.317 | 2462.627 | 265.57 | n/a | 111831.04 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 23 / 8388608 | 2 | 1045.705 | 1383.126 | 84.179 | 2428.831 | 269.49 | n/a | 154716.16 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 24 / 16777216 | 2 | 1633.182 | 2496.886 | 115.111 | 4130.068 | 290.82 | n/a | 223621.12 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 18 / 262144 | 2 | 133.079 | 3.370 | 8.408 | 136.449 | 980.35 | n/a | 4373.05 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 19 / 524288 | 2 | 268.333 | 3.833 | 9.824 | 272.166 | 1097.37 | n/a | 8488.40 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 20 / 1048576 | 2 | 532.084 | 5.049 | 11.006 | 537.133 | 1259.96 | n/a | 16711.09 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 21 / 2097152 | 2 | 1083.886 | 7.593 | 11.901 | 1091.479 | 1435.38 | n/a | 33122.56 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 22 / 4194304 | 2 | 2132.481 | 12.450 | 13.414 | 2144.931 | 1590.84 | n/a | 65916.62 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 23 / 8388608 | 2 | 4252.207 | 22.652 | 13.804 | 4274.859 | 1777.92 | n/a | 131481.62 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 24 / 16777216 | 2 | 8640.677 | 43.133 | 15.149 | 8683.810 | 1952.75 | n/a | 262578.71 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 18 / 262144 | 2 | 51.778 | 19.454 | 1.541 | 71.232 | 134.36 | n/a | 4302.58 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 19 / 524288 | 2 | 101.379 | 34.340 | 2.344 | 135.719 | 159.02 | n/a | 8541.21 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 20 / 1048576 | 2 | 197.677 | 61.186 | 1.972 | 258.863 | 183.27 | n/a | 17013.18 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 21 / 2097152 | 2 | 394.986 | 119.057 | 2.504 | 514.043 | 215.20 | n/a | 33907.89 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 22 / 4194304 | 2 | 815.491 | 232.441 | 2.525 | 1047.932 | 246.30 | n/a | 67721.99 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 23 / 8388608 | 2 | 1804.366 | 497.806 | 2.867 | 2302.172 | 285.11 | n/a | 135312.93 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 24 / 16777216 | 2 | 3512.492 | 467.282 | 3.132 | 3979.774 | 324.48 | n/a | 266417.27 | scheme_native_reported | 1 |

## dePCS Proof Size Components

- Detailed per-run charts are written as `proof_size_component_breakdown_by_nv.svg` inside each `pcs-bench-*` artifact directory.
- dePCS nv=18 workers=2: largest proof component is `column_openings` at 290.54 KiB (64.2% of proof KiB).
- dePCS nv=19 workers=2: largest proof component is `column_openings` at 340.32 KiB (64.4% of proof KiB).
- dePCS nv=20 workers=2: largest proof component is `column_openings` at 398.92 KiB (64.7% of proof KiB).
- dePCS nv=21 workers=2: largest proof component is `column_openings` at 456.88 KiB (64.9% of proof KiB).
- dePCS nv=22 workers=2: largest proof component is `column_openings` at 517.01 KiB (65.0% of proof KiB).
- dePCS nv=23 workers=2: largest proof component is `column_openings` at 583.23 KiB (65.1% of proof KiB).
- dePCS nv=24 workers=2: largest proof component is `column_openings` at 652.16 KiB (65.3% of proof KiB).
- dePCS nv=18 workers=2: largest proof component is `column_openings` at 457.95 KiB (65.0% of proof KiB).
- dePCS nv=19 workers=2: largest proof component is `column_openings` at 524.71 KiB (65.2% of proof KiB).
- dePCS nv=20 workers=2: largest proof component is `column_openings` at 602.49 KiB (65.3% of proof KiB).
- dePCS nv=21 workers=2: largest proof component is `column_openings` at 680.21 KiB (65.4% of proof KiB).
- dePCS nv=22 workers=2: largest proof component is `column_openings` at 758.06 KiB (65.5% of proof KiB).
- dePCS nv=23 workers=2: largest proof component is `column_openings` at 853.70 KiB (65.6% of proof KiB).
- dePCS nv=24 workers=2: largest proof component is `column_openings` at 943.12 KiB (65.7% of proof KiB).

## Notes

- fair_sequential: one benchmark row at a time; host_logical_cores=20; max_workers=2; cores_per_worker=10.
- query_semantics: dePCS uses paper-backed backend query policy; dFRIttata, dPIP-FRI, and LigeSIS remain scheme-native by default.
