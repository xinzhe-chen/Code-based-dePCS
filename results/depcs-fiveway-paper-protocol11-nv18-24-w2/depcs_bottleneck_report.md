# dePCS Bottleneck Investigation

- generated_at: 2026-06-25T20:58:07
- scope: prover time, verifier time, proof size, communication cost, and linear scalability.
- root_cause_labels: `implementation-centralized`, `backend-batching-missing`, `protocol-inherent`.

## Headline At Largest Point

| scheme | prover ms | verify ms | proof KiB | comm KiB |
| --- | ---: | ---: | ---: | ---: |
| LigeSIS dLigesis | 5647.925 | 192.619 | 290.82 | n/a |
| dFRIttata-PCS | 9820.014 | 19.560 | 1946.41 | n/a |
| dPIP-FRI-PCS | 4864.321 | 4.455 | 336.64 | n/a |
| dePCS_Basefold | 117710.380 | 5631.637 | 1420.91 | 1429.90 |
| dePCS_Deepfold | 14392.224 | 789.478 | 985.69 | 994.09 |

## dePCS Vs External Ratios

| dePCS row | external row | prover | verify | proof | communication |
| --- | --- | ---: | ---: | ---: | ---: |
| dePCS_Basefold nv=18 w=2 | best at nv=18, workers=2 | 7.49x | 34.88x | 5.22x | n/a |
| dePCS_Deepfold nv=18 w=2 | best at nv=18, workers=2 | 2.34x | 12.30x | 3.34x | n/a |
| dePCS_Basefold nv=19 w=2 | best at nv=19, workers=2 | 10.05x | 45.60x | 5.03x | n/a |
| dePCS_Deepfold nv=19 w=2 | best at nv=19, workers=2 | 2.30x | 13.56x | 3.29x | n/a |
| dePCS_Basefold nv=20 w=2 | best at nv=20, workers=2 | 5.30x | 118.82x | 4.98x | n/a |
| dePCS_Deepfold nv=20 w=2 | best at nv=20, workers=2 | 1.45x | 16.29x | 3.33x | n/a |
| dePCS_Basefold nv=21 w=2 | best at nv=21, workers=2 | 11.50x | 231.62x | 4.89x | n/a |
| dePCS_Deepfold nv=21 w=2 | best at nv=21, workers=2 | 3.36x | 25.83x | 3.29x | n/a |
| dePCS_Basefold nv=22 w=2 | best at nv=22, workers=2 | 13.53x | 563.25x | 4.70x | n/a |
| dePCS_Deepfold nv=22 w=2 | best at nv=22, workers=2 | 2.02x | 86.07x | 3.22x | n/a |
| dePCS_Basefold nv=23 w=2 | best at nv=23, workers=2 | 17.28x | 1156.24x | 4.74x | n/a |
| dePCS_Deepfold nv=23 w=2 | best at nv=23, workers=2 | 2.50x | 120.25x | 3.27x | n/a |
| dePCS_Basefold nv=24 w=2 | best at nv=24, workers=2 | 24.20x | 1264.12x | 4.89x | n/a |
| dePCS_Deepfold nv=24 w=2 | best at nv=24, workers=2 | 2.96x | 177.21x | 3.39x | n/a |

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
| depcs-basefold-paper-protocol11 | 18 | 2 | 3.94 | 696.38 | 692.55 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 4.04 | 797.79 | 793.84 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 4.13 | 906.14 | 902.09 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 4.22 | 1025.71 | 1021.55 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 4.32 | 1149.63 | 1145.36 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 4.41 | 1281.66 | 1277.28 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 4.50 | 1425.39 | 1420.91 | 0.0 | 0.0 | 66.4 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 3.64 | 447.47 | 443.94 | 0.0 | 0.0 | 66.0 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 3.74 | 521.60 | 517.95 | 0.0 | 0.0 | 66.1 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 3.83 | 607.32 | 603.56 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 3.93 | 690.39 | 686.53 | 0.0 | 0.0 | 66.2 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 4.02 | 789.63 | 785.66 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 4.11 | 885.71 | 881.62 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 4.21 | 989.88 | 985.69 | 0.0 | 0.0 | 66.3 | 0.0 | 4 |

## Paper Artifact Timing Breakdown

| scheme | nv | workers | wall commit | worker commit max | worker commit sum | wall open | worker open max | worker open sum | master assemble | wall verify | worker verify max | worker verify sum | master verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| depcs-basefold-paper-protocol11 | 18 | 2 | 326.730 | 326.480 | 642.139 | 213.746 | 206.048 | 408.325 | 6.765 | 53.019 | 46.527 | 92.653 | 53.013 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 799.406 | 798.998 | 1589.067 | 596.671 | 589.168 | 1178.049 | 5.896 | 98.319 | 92.033 | 177.989 | 98.314 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 1351.592 | 1351.320 | 2683.794 | 852.405 | 839.998 | 1608.132 | 9.508 | 368.447 | 357.125 | 711.101 | 368.438 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 3628.647 | 3628.155 | 6887.269 | 3034.327 | 3014.771 | 6022.732 | 14.881 | 799.325 | 785.675 | 1569.493 | 799.315 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 10654.004 | 10653.562 | 20252.784 | 5915.300 | 5900.141 | 11706.399 | 13.177 | 1476.276 | 1462.740 | 2916.886 | 1476.266 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 25044.888 | 25044.470 | 49623.952 | 19409.016 | 19383.107 | 38077.974 | 20.472 | 4221.419 | 4191.385 | 8378.846 | 4221.408 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 65206.192 | 65203.431 | 129923.698 | 52504.188 | 52484.433 | 99480.719 | 16.002 | 5631.637 | 5612.599 | 11207.778 | 5631.624 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 78.240 | 77.952 | 154.919 | 90.797 | 86.320 | 170.558 | 3.130 | 18.697 | 14.601 | 27.296 | 18.692 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 172.799 | 172.462 | 344.857 | 146.519 | 142.117 | 280.234 | 3.259 | 29.235 | 24.793 | 49.184 | 29.229 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 339.940 | 339.652 | 672.814 | 262.485 | 256.984 | 508.525 | 4.279 | 50.520 | 45.360 | 89.832 | 50.515 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 1425.979 | 1425.615 | 2849.989 | 522.148 | 516.466 | 1031.492 | 4.783 | 89.124 | 83.917 | 166.454 | 89.121 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 1457.702 | 1457.321 | 2889.538 | 1015.991 | 1008.558 | 1970.971 | 5.749 | 225.599 | 219.122 | 433.563 | 225.594 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 3874.413 | 3873.890 | 7653.384 | 2568.408 | 2558.316 | 5075.437 | 7.902 | 439.050 | 429.296 | 853.996 | 439.044 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 8443.224 | 8442.936 | 16478.200 | 5949.000 | 5940.399 | 11799.709 | 7.339 | 789.478 | 782.399 | 1560.290 | 789.470 |

## Scheme Differences

- dePCS proves a Brakedown-style Protocol 11 evaluation plus two Protocol 10 encoding relations over independent per-worker transparent PC commitments.
- LigeSIS uses SIS hashing plus DeepFold multi-chunked batch openings and extension-field sumchecks, which keeps verifier-facing proof size small but can send more network data at high party counts.
- dFRIttata follows a FRI fold-and-batch path and avoids dePCS Protocol 10/11 encoding consistency proof shape.
- dPIP-FRI is a specialized distributed PIP-FRI path; it has much smaller proof/verifier/communication constants but is not the same dePCS Brakedown protocol.
