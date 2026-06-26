# dePCS Bottleneck Investigation

- generated_at: 2026-06-25T23:15:29
- scope: prover time, verifier time, proof size, communication cost, and linear scalability.
- root_cause_labels: `implementation-centralized`, `backend-batching-missing`, `protocol-inherent`.

## Headline At Largest Point

| scheme | prover ms | verify ms | proof KiB | comm KiB |
| --- | ---: | ---: | ---: | ---: |
| LigeSIS dLigesis | 4283.595 | 115.301 | 290.82 | n/a |
| dFRIttata-PCS | 8604.523 | 14.600 | 1950.10 | n/a |
| dPIP-FRI-PCS | 4084.100 | 3.640 | 332.64 | n/a |
| dePCS_Basefold | 113831.172 | 5525.225 | 1420.31 | 1429.30 |
| dePCS_Basefold | 0.000 | 0.000 | 0.00 | n/a |
| dePCS_Deepfold | 17300.574 | 1369.724 | 993.84 | 1002.24 |
| dePCS_Deepfold | 0.000 | 0.000 | 0.00 | n/a |

## dePCS Vs External Ratios

| dePCS row | external row | prover | verify | proof | communication |
| --- | --- | ---: | ---: | ---: | ---: |
| dePCS_Basefold nv=18 w=2 | best at nv=18, workers=2 | 6.51x | 27.86x | 5.31x | n/a |
| dePCS_Basefold nv=18 w=2 | best at nv=18, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=18 w=2 | best at nv=18, workers=2 | 1.94x | 9.96x | 3.35x | n/a |
| dePCS_Deepfold nv=18 w=2 | best at nv=18, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=19 w=2 | best at nv=19, workers=2 | 7.53x | 50.86x | 5.10x | n/a |
| dePCS_Basefold nv=19 w=2 | best at nv=19, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=19 w=2 | best at nv=19, workers=2 | 2.13x | 14.91x | 3.37x | n/a |
| dePCS_Deepfold nv=19 w=2 | best at nv=19, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=20 w=2 | best at nv=20, workers=2 | 8.17x | 179.26x | 4.99x | n/a |
| dePCS_Basefold nv=20 w=2 | best at nv=20, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=20 w=2 | best at nv=20, workers=2 | 2.08x | 23.94x | 3.32x | n/a |
| dePCS_Deepfold nv=20 w=2 | best at nv=20, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=21 w=2 | best at nv=21, workers=2 | 10.67x | 311.31x | 4.85x | n/a |
| dePCS_Basefold nv=21 w=2 | best at nv=21, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=21 w=2 | best at nv=21, workers=2 | 2.27x | 37.07x | 3.26x | n/a |
| dePCS_Deepfold nv=21 w=2 | best at nv=21, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=22 w=2 | best at nv=22, workers=2 | 13.87x | 523.97x | 4.80x | n/a |
| dePCS_Basefold nv=22 w=2 | best at nv=22, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=22 w=2 | best at nv=22, workers=2 | 2.10x | 136.32x | 3.28x | n/a |
| dePCS_Deepfold nv=22 w=2 | best at nv=22, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=23 w=2 | best at nv=23, workers=2 | 15.98x | 448.22x | 4.76x | n/a |
| dePCS_Basefold nv=23 w=2 | best at nv=23, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=23 w=2 | best at nv=23, workers=2 | 2.76x | 246.72x | 3.26x | n/a |
| dePCS_Deepfold nv=23 w=2 | best at nv=23, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Basefold nv=24 w=2 | best at nv=24, workers=2 | 27.87x | 1517.92x | 4.88x | n/a |
| dePCS_Basefold nv=24 w=2 | best at nv=24, workers=2 | 0.00x | 0.00x | 0.00x | n/a |
| dePCS_Deepfold nv=24 w=2 | best at nv=24, workers=2 | 4.24x | 376.30x | 3.42x | n/a |
| dePCS_Deepfold nv=24 w=2 | best at nv=24, workers=2 | 0.00x | 0.00x | 0.00x | n/a |

## Root Cause Matrix

| metric | observed dePCS bottleneck | root cause | optimization status |
| --- | --- | --- | --- |
| prover time | paper-backed rows separate distributed wall-clock from worker-local artifact PCS commit/open max and sum. | implementation-centralized + protocol-inherent | worker commit now caches prepared artifact prover state; open reuses the cache and no longer rebuilds initial interpolation/Merkle state. Remaining cost is artifact PCS proof generation plus Protocol10/11 assembly. |
| verifier time | paper-backed rows separate independent worker artifact verification from master Protocol10/11 checks. | backend-batching-missing | independent artifact proofs are verified in parallel; no unsupported artifact batch verify API is claimed. |
| proof size | e1/e2 Protocol 10 proofs are typically the largest components. | backend-batching-missing | duplicate source commitments in Protocol 10 weighted openings are now opened once with accumulated weight; different independent roots still need separate paths. |
| communication cost | network open bytes dominate total communication. | implementation-centralized | commit rows, JSON bloat, full encoded rows, and redundant e/f vectors are removed from the benchmark path; communication now includes worker column-proof fragments. |
| linear scalability | end-to-end open/proof speedup flattens or regresses at high workers. | implementation-centralized | staged column proofs make the distributed boundary explicit; remaining aggregation and combined-PC proof construction are still centralized. |

## dePCS Raw Component Breakdown

| scheme | nv | workers | commit KiB | open KiB | proof KiB | p10 e1 % | p10 e2 % | column % | f2 % | batch claims |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| depcs-basefold-paper-protocol11 | 18 | 2 | 3.94 | 697.13 | 693.30 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 4.04 | 793.86 | 789.92 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 4.13 | 909.61 | 905.56 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 4.22 | 1026.27 | 1022.11 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 4.32 | 1151.99 | 1147.72 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 4.41 | 1288.22 | 1283.84 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 4.50 | 1424.80 | 1420.31 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 3.64 | 441.11 | 437.58 | 0.0 | 0.0 | 66.0 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 3.74 | 526.47 | 522.83 | 0.0 | 0.0 | 66.1 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 3.83 | 606.25 | 602.50 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 3.93 | 690.05 | 686.19 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 4.02 | 789.66 | 785.69 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 4.11 | 881.79 | 877.70 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 4.21 | 998.04 | 993.84 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |

## Paper Artifact Timing Breakdown

| scheme | nv | workers | wall commit | worker commit max | worker commit sum | wall open | worker open max | worker open sum | master assemble | wall verify | worker verify max | worker verify sum | master verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| depcs-basefold-paper-protocol11 | 18 | 2 | 313.303 | 312.811 | 625.127 | 178.905 | 173.602 | 346.640 | 4.480 | 45.242 | 40.107 | 79.951 | 45.237 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 620.079 | 619.337 | 1234.472 | 350.407 | 343.953 | 687.808 | 5.178 | 89.419 | 83.855 | 166.340 | 89.414 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 1350.354 | 1349.673 | 2699.042 | 739.482 | 727.471 | 1423.997 | 9.524 | 356.378 | 346.002 | 691.121 | 356.368 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 2934.052 | 2933.603 | 5503.104 | 2437.050 | 2422.046 | 4839.431 | 11.410 | 705.427 | 693.030 | 1379.480 | 705.415 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 9742.147 | 9741.443 | 18055.969 | 4999.064 | 4983.990 | 9952.548 | 12.509 | 1378.028 | 1363.642 | 2717.880 | 1378.017 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 23967.566 | 23966.859 | 47495.498 | 12604.976 | 12593.078 | 24970.139 | 8.879 | 1285.041 | 1275.317 | 2542.856 | 1285.033 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 62414.773 | 62411.818 | 124789.567 | 51416.399 | 51399.831 | 99075.035 | 10.067 | 5525.225 | 5506.622 | 11003.274 | 5525.216 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 71.404 | 71.020 | 141.979 | 75.632 | 72.054 | 140.610 | 2.925 | 16.178 | 12.729 | 25.174 | 16.173 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 148.408 | 148.039 | 293.904 | 126.169 | 121.834 | 241.065 | 3.353 | 26.211 | 21.977 | 43.460 | 26.204 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 307.785 | 307.376 | 607.810 | 223.408 | 218.496 | 436.122 | 3.744 | 47.602 | 42.912 | 85.027 | 47.595 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 669.104 | 668.750 | 1333.930 | 475.855 | 470.694 | 938.898 | 4.416 | 83.997 | 78.965 | 157.536 | 83.991 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 1335.863 | 1335.615 | 2669.719 | 899.139 | 888.072 | 1688.005 | 8.618 | 358.510 | 348.504 | 695.127 | 358.493 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 3328.550 | 3328.179 | 6232.643 | 2990.717 | 2979.071 | 5941.505 | 9.919 | 707.337 | 696.025 | 1389.060 | 707.326 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 11012.088 | 11011.650 | 20757.791 | 6288.486 | 6264.183 | 12493.327 | 10.664 | 1369.724 | 1357.933 | 2711.675 | 1369.712 |

## Scheme Differences

- dePCS proves a Brakedown-style Protocol 11 evaluation plus two Protocol 10 encoding relations over independent per-worker transparent PC commitments.
- LigeSIS uses SIS hashing plus DeepFold multi-chunked batch openings and extension-field sumchecks, which keeps verifier-facing proof size small but can send more network data at high party counts.
- dFRIttata follows a FRI fold-and-batch path and avoids dePCS Protocol 10/11 encoding consistency proof shape.
- dPIP-FRI is a specialized distributed PIP-FRI path; it has much smaller proof/verifier/communication constants but is not the same dePCS Brakedown protocol.
