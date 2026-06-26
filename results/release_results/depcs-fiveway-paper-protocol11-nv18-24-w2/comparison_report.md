# dePCS BaseFold vs DeepFold vs External PCS Benchmark Report

- generated_at: 2026-06-25T20:58:07
- depcs_artifact_dirs: `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391920408`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391921832`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391923398`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391925283`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391928577`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391932584`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391941434`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391958058`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391959892`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391962630`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391966478`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391975258`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782391994753`, `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-nv18-24-w2\pcs-bench-1782392046242`
- benchmark_design: fair sequential reproduction over nv=18..24; each benchmark row (scheme,nv,workers) runs alone with a per-row timeout, after release binaries are built.
- size_semantics: nv is the number of multilinear polynomial variables; polynomial length is N=2^nv. These are PCS sizes, not circuit gate counts.
- scheduling: strict row order is depcs-deepfold, depcs-basefold, LigeSIS, dFRIttata, dPIP-FRI; within each scheme rows run nv ascending then workers ascending. host_logical_cores=20, max_workers=2, cores_per_worker=10. protocol11 dePCS rows must report master/worker network sent+recv bytes; paper-native rows are PCS-only and external party processes use cores_per_worker threads each.
- timeout_policy: fair rows use per-row timeouts: dePCS=600s, LigeSIS=900s, external=900s; a timeout marks only that row blocked.
- query_count_semantics: dePCS BaseFold/DeepFold use the paper-backed backend query policy; dFRIttata, dPIP-FRI, and LigeSIS use their scheme-native query settings unless `--force-external-query-count` is explicitly set.
- proof_size_semantics: `proof KiB` is the verifier-received PCS commitment object plus PCS opening proof. It is not prover-local committed polynomial storage.
- communication_semantics: `dePCS send+recv KiB` is only master/worker network sent plus received bytes from dePCS protocol11 rows. External and LigeSIS native communication is reported separately as `native comm KiB`; `communication_cost_kib` is a chart-only derived value with `communication_cost_basis`.
- verifier_semantics: paper-backed dePCS uses parallel independent artifact PCS verification plus batched Protocol10/11 consistency checks; no unsupported artifact batch-verify API is assumed.
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
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 18 / 262144 | 2 | 78.240 | 90.797 | 18.697 | 169.037 | 443.94 | 451.12 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 19 / 524288 | 2 | 172.799 | 146.519 | 29.235 | 319.318 | 517.95 | 525.34 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 20 / 1048576 | 2 | 339.940 | 262.485 | 50.520 | 602.425 | 603.56 | 611.15 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 21 / 2097152 | 2 | 1425.979 | 522.148 | 89.124 | 1948.128 | 686.53 | 694.32 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 22 / 4194304 | 2 | 1457.702 | 1015.991 | 225.599 | 2473.693 | 785.66 | 793.65 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 23 / 8388608 | 2 | 3874.413 | 2568.408 | 439.050 | 6442.822 | 881.62 | 889.82 | n/a | master_worker_sent_recv | 1 |
| dePCS_Deepfold | deepfold | 2 | paper-network-protocol11 | protocol11 | 24 / 16777216 | 2 | 8443.224 | 5949.000 | 789.478 | 14392.224 | 985.69 | 994.09 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 18 / 262144 | 2 | 326.730 | 213.746 | 53.019 | 540.476 | 692.55 | 700.32 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 19 / 524288 | 2 | 799.406 | 596.671 | 98.319 | 1396.077 | 793.84 | 801.82 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 20 / 1048576 | 2 | 1351.592 | 852.405 | 368.447 | 2203.998 | 902.09 | 910.27 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 21 / 2097152 | 2 | 3628.647 | 3034.327 | 799.325 | 6662.974 | 1021.55 | 1029.93 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 22 / 4194304 | 2 | 10654.004 | 5915.300 | 1476.276 | 16569.303 | 1145.36 | 1153.95 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 23 / 8388608 | 2 | 25044.888 | 19409.016 | 4221.419 | 44453.905 | 1277.28 | 1286.07 | n/a | master_worker_sent_recv | 1 |
| dePCS_Basefold | basefold | 8 | paper-network-protocol11 | protocol11 | 24 / 16777216 | 2 | 65206.192 | 52504.188 | 5631.637 | 117710.380 | 1420.91 | 1429.90 | n/a | master_worker_sent_recv | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 18 / 262144 | 2 | 114.332 | 335.988 | 15.049 | 450.320 | 218.51 | n/a | 28006.40 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 19 / 524288 | 2 | 157.484 | 369.602 | 20.511 | 527.086 | 222.26 | n/a | 38717.44 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 20 / 1048576 | 2 | 178.517 | 618.294 | 29.364 | 796.811 | 241.47 | n/a | 55941.12 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 21 / 2097152 | 2 | 345.109 | 698.397 | 40.086 | 1043.506 | 245.30 | n/a | 77373.44 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 22 / 4194304 | 2 | 538.688 | 1253.860 | 57.057 | 1792.548 | 265.57 | n/a | 111831.04 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 23 / 8388608 | 2 | 1060.921 | 1511.238 | 134.484 | 2572.159 | 269.49 | n/a | 154716.16 | scheme_native_reported | 1 |
| LigeSIS dLigesis | ligesis | 0 | local | dligesis | 24 / 16777216 | 2 | 1696.786 | 3951.139 | 192.619 | 5647.925 | 290.82 | n/a | 223621.12 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 18 / 262144 | 2 | 140.150 | 3.180 | 9.171 | 143.330 | 979.26 | n/a | 4371.81 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 19 / 524288 | 2 | 274.263 | 4.066 | 10.129 | 278.329 | 1115.22 | n/a | 8493.15 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 20 / 1048576 | 2 | 692.611 | 6.118 | 13.291 | 698.729 | 1264.97 | n/a | 16713.06 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 21 / 2097152 | 2 | 1123.911 | 7.384 | 12.338 | 1131.295 | 1419.09 | n/a | 33120.80 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 22 / 4194304 | 2 | 2504.241 | 28.756 | 17.570 | 2532.997 | 1606.13 | n/a | 65919.90 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 23 / 8388608 | 2 | 5008.678 | 38.262 | 16.300 | 5046.940 | 1783.49 | n/a | 131483.34 | scheme_native_reported | 1 |
| dFRIttata-PCS | frittata | 0 | local | dfrittata | 24 / 16777216 | 2 | 9764.298 | 55.716 | 19.560 | 9820.014 | 1946.41 | n/a | 262578.31 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 18 / 262144 | 2 | 52.241 | 19.949 | 1.520 | 72.190 | 132.77 | n/a | 4305.64 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 19 / 524288 | 2 | 104.911 | 33.938 | 2.156 | 138.849 | 157.67 | n/a | 8533.64 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 20 / 1048576 | 2 | 343.904 | 71.820 | 3.101 | 415.724 | 181.20 | n/a | 17001.68 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 21 / 2097152 | 2 | 453.322 | 126.061 | 3.451 | 579.383 | 208.95 | n/a | 33899.61 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 22 / 4194304 | 2 | 978.505 | 246.431 | 2.621 | 1224.936 | 243.67 | n/a | 67723.74 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 23 / 8388608 | 2 | 2145.604 | 597.639 | 3.651 | 2743.243 | 284.80 | n/a | 135334.18 | scheme_native_reported | 1 |
| dPIP-FRI-PCS | pip-fri | 0 | local | depipfri | 24 / 16777216 | 2 | 4219.886 | 644.435 | 4.455 | 4864.321 | 336.64 | n/a | 266429.27 | scheme_native_reported | 1 |

## dePCS Proof Size Components

- Detailed per-run charts are written as `proof_size_component_breakdown_by_nv.svg` inside each `pcs-bench-*` artifact directory.
- dePCS nv=18 workers=2: largest proof component is `column_openings` at 293.08 KiB (66.0% of proof KiB).
- dePCS nv=19 workers=2: largest proof component is `column_openings` at 342.35 KiB (66.1% of proof KiB).
- dePCS nv=20 workers=2: largest proof component is `column_openings` at 399.35 KiB (66.2% of proof KiB).
- dePCS nv=21 workers=2: largest proof component is `column_openings` at 454.59 KiB (66.2% of proof KiB).
- dePCS nv=22 workers=2: largest proof component is `column_openings` at 520.60 KiB (66.3% of proof KiB).
- dePCS nv=23 workers=2: largest proof component is `column_openings` at 584.51 KiB (66.3% of proof KiB).
- dePCS nv=24 workers=2: largest proof component is `column_openings` at 653.81 KiB (66.3% of proof KiB).
- dePCS nv=18 workers=2: largest proof component is `column_openings` at 458.62 KiB (66.2% of proof KiB).
- dePCS nv=19 workers=2: largest proof component is `column_openings` at 526.08 KiB (66.3% of proof KiB).
- dePCS nv=20 workers=2: largest proof component is `column_openings` at 598.18 KiB (66.3% of proof KiB).
- dePCS nv=21 workers=2: largest proof component is `column_openings` at 677.74 KiB (66.3% of proof KiB).
- dePCS nv=22 workers=2: largest proof component is `column_openings` at 760.21 KiB (66.4% of proof KiB).
- dePCS nv=23 workers=2: largest proof component is `column_openings` at 848.08 KiB (66.4% of proof KiB).
- dePCS nv=24 workers=2: largest proof component is `column_openings` at 943.76 KiB (66.4% of proof KiB).

## Notes

- fair_sequential: one benchmark row at a time; host_logical_cores=20; max_workers=2; cores_per_worker=10.
- query_semantics: dePCS uses paper-backed backend query policy; dFRIttata, dPIP-FRI, and LigeSIS remain scheme-native by default.
