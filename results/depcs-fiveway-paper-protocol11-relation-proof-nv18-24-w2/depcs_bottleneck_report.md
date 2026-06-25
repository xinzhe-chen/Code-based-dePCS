# dePCS Bottleneck Investigation

- generated_at: 2026-06-25T23:33:26
- scope: prover time, verifier time, proof size, communication cost, and linear scalability.
- root_cause_labels: `implementation-centralized`, `backend-batching-missing`, `protocol-inherent`.

## Headline At Largest Point

| scheme | prover ms | verify ms | proof KiB | comm KiB |
| --- | ---: | ---: | ---: | ---: |
| LigeSIS dLigesis | 4131.635 | 115.565 | 290.82 | n/a |
| dFRIttata-PCS | 8764.317 | 15.853 | 1966.79 | n/a |
| dPIP-FRI-PCS | 3923.384 | 3.467 | 334.39 | n/a |
| dePCS_Basefold | 73641.739 | 2595.216 | 1438.96 | 1431.87 |
| dePCS_Deepfold | 12060.618 | 795.025 | 995.27 | 987.59 |

## dePCS Vs External Ratios

| dePCS row | external row | prover | verify | proof | communication |
| --- | --- | ---: | ---: | ---: | ---: |
| dePCS_Basefold nv=18 w=2 | best at nv=18, workers=2 | 7.89x | 31.91x | 5.18x | n/a |
| dePCS_Deepfold nv=18 w=2 | best at nv=18, workers=2 | 2.50x | 10.72x | 3.34x | n/a |
| dePCS_Basefold nv=19 w=2 | best at nv=19, workers=2 | 7.98x | 49.39x | 5.01x | n/a |
| dePCS_Deepfold nv=19 w=2 | best at nv=19, workers=2 | 2.32x | 15.82x | 3.30x | n/a |
| dePCS_Basefold nv=20 w=2 | best at nv=20, workers=2 | 7.78x | 77.54x | 4.97x | n/a |
| dePCS_Deepfold nv=20 w=2 | best at nv=20, workers=2 | 2.22x | 21.06x | 3.35x | n/a |
| dePCS_Basefold nv=21 w=2 | best at nv=21, workers=2 | 7.70x | 119.16x | 4.78x | n/a |
| dePCS_Deepfold nv=21 w=2 | best at nv=21, workers=2 | 2.00x | 33.96x | 3.28x | n/a |
| dePCS_Basefold nv=22 w=2 | best at nv=22, workers=2 | 7.76x | 249.68x | 4.78x | n/a |
| dePCS_Deepfold nv=22 w=2 | best at nv=22, workers=2 | 2.21x | 78.26x | 3.29x | n/a |
| dePCS_Basefold nv=23 w=2 | best at nv=23, workers=2 | 8.04x | 426.49x | 4.81x | n/a |
| dePCS_Deepfold nv=23 w=2 | best at nv=23, workers=2 | 2.12x | 142.58x | 3.35x | n/a |
| dePCS_Basefold nv=24 w=2 | best at nv=24, workers=2 | 18.77x | 748.55x | 4.95x | n/a |
| dePCS_Deepfold nv=24 w=2 | best at nv=24, workers=2 | 3.07x | 229.31x | 3.42x | n/a |

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
| depcs-basefold-paper-protocol11 | 18 | 2 | 3.94 | 691.18 | 700.05 | 0.9 | 0.9 | 65.0 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 4.04 | 798.72 | 808.05 | 0.8 | 0.8 | 65.2 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 4.13 | 900.30 | 910.09 | 0.8 | 0.8 | 65.3 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 4.22 | 1016.63 | 1026.87 | 0.7 | 0.7 | 65.4 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 4.32 | 1152.36 | 1163.05 | 0.7 | 0.7 | 65.5 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 4.41 | 1286.22 | 1297.37 | 0.6 | 0.6 | 65.6 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 4.50 | 1427.36 | 1438.96 | 0.6 | 0.6 | 65.7 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 3.64 | 443.10 | 452.27 | 1.4 | 1.4 | 64.2 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 3.74 | 521.97 | 531.60 | 1.3 | 1.3 | 64.4 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 3.83 | 603.27 | 613.35 | 1.2 | 1.2 | 64.7 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 3.93 | 693.71 | 704.24 | 1.0 | 1.0 | 64.9 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 4.02 | 788.14 | 799.13 | 1.0 | 1.0 | 65.0 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 4.11 | 890.19 | 901.63 | 0.9 | 0.9 | 65.2 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 4.21 | 983.38 | 995.27 | 0.8 | 0.8 | 65.3 | 0.0 | 16 |

## Paper Artifact Timing Breakdown

| scheme | nv | workers | wall commit | worker commit max | worker commit sum | wall open | worker open max | worker open sum | master assemble | wall verify | worker verify max | worker verify sum | master verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| depcs-basefold-paper-protocol11 | 18 | 2 | 353.611 | 353.294 | 692.707 | 196.738 | 190.783 | 380.232 | 4.668 | 48.187 | 42.668 | 84.044 | 48.181 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 666.789 | 666.477 | 1316.371 | 391.773 | 383.773 | 766.266 | 5.674 | 86.928 | 81.097 | 156.453 | 86.925 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 1308.429 | 1308.149 | 2588.448 | 698.702 | 691.013 | 1380.643 | 6.053 | 174.696 | 167.613 | 334.376 | 174.691 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 2812.650 | 2812.258 | 5551.325 | 1418.875 | 1410.271 | 2804.901 | 6.631 | 306.949 | 299.833 | 599.210 | 306.945 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 5331.045 | 5330.732 | 10602.709 | 2804.984 | 2794.843 | 5557.617 | 8.118 | 627.702 | 619.778 | 1238.979 | 627.698 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 11015.118 | 11014.730 | 21931.996 | 7953.856 | 7942.714 | 15573.888 | 9.351 | 1210.369 | 1201.347 | 2395.026 | 1210.365 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 34470.952 | 34469.651 | 68754.817 | 39170.787 | 39156.457 | 75068.003 | 9.846 | 2595.216 | 2583.852 | 5166.533 | 2595.207 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 76.952 | 76.693 | 152.895 | 97.746 | 76.093 | 149.255 | 3.229 | 16.184 | 12.789 | 25.576 | 16.181 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 175.291 | 174.920 | 334.872 | 132.722 | 128.398 | 250.607 | 3.570 | 27.847 | 23.840 | 46.644 | 27.842 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 326.172 | 325.897 | 646.680 | 247.087 | 242.092 | 479.720 | 4.217 | 47.448 | 42.925 | 83.805 | 47.446 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 663.363 | 663.085 | 1324.508 | 435.905 | 430.167 | 852.310 | 4.882 | 87.482 | 81.801 | 162.401 | 87.479 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 1391.266 | 1390.761 | 2765.974 | 922.023 | 912.067 | 1786.336 | 7.674 | 196.749 | 189.986 | 378.764 | 196.744 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 3086.496 | 3086.158 | 6086.050 | 1910.121 | 1901.142 | 3767.057 | 7.659 | 404.631 | 397.853 | 781.558 | 404.628 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 7734.776 | 7734.388 | 15307.474 | 4325.843 | 4316.819 | 8598.980 | 7.371 | 795.025 | 785.108 | 1569.657 | 795.020 |

## Scheme Differences

- dePCS proves a Brakedown-style Protocol 11 evaluation plus two Protocol 10 encoding relations over independent per-worker transparent PC commitments.
- LigeSIS uses SIS hashing plus DeepFold multi-chunked batch openings and extension-field sumchecks, which keeps verifier-facing proof size small but can send more network data at high party counts.
- dFRIttata follows a FRI fold-and-batch path and avoids dePCS Protocol 10/11 encoding consistency proof shape.
- dPIP-FRI is a specialized distributed PIP-FRI path; it has much smaller proof/verifier/communication constants but is not the same dePCS Brakedown protocol.

## dePCS Before After

- baseline: `C:\Projects\pq_dSNARK\results\depcs-fiveway-paper-protocol11-batch-audit-nv18-24-w2`

| row | prover | verify | proof | communication |
| --- | ---: | ---: | ---: | ---: |
| depcs-deepfold-paper-protocol11 nv=18 w=2 | 147.036 -> 174.698 | 16.178 -> 16.184 | 437.58 -> 452.27 | 444.76 -> 446.74 |
| depcs-deepfold-paper-protocol11 nv=19 w=2 | 274.577 -> 308.013 | 26.211 -> 27.847 | 522.83 -> 531.60 | 530.21 -> 525.71 |
| depcs-deepfold-paper-protocol11 nv=20 w=2 | 531.193 -> 573.259 | 47.602 -> 47.448 | 602.50 -> 613.35 | 610.09 -> 607.10 |
| depcs-deepfold-paper-protocol11 nv=21 w=2 | 1144.959 -> 1099.269 | 83.997 -> 87.482 | 686.19 -> 704.24 | 693.98 -> 697.63 |
| depcs-deepfold-paper-protocol11 nv=22 w=2 | 2235.002 -> 2313.288 | 358.510 -> 196.749 | 785.69 -> 799.13 | 793.68 -> 792.16 |
| depcs-deepfold-paper-protocol11 nv=23 w=2 | 6319.267 -> 4996.617 | 707.337 -> 404.631 | 877.70 -> 901.63 | 885.90 -> 894.30 |
| depcs-deepfold-paper-protocol11 nv=24 w=2 | 17300.574 -> 12060.618 | 1369.724 -> 795.025 | 993.84 -> 995.27 | 1002.24 -> 987.59 |
| depcs-basefold-paper-protocol11 nv=18 w=2 | 492.208 -> 550.349 | 45.242 -> 48.187 | 693.30 -> 700.05 | 701.07 -> 695.12 |
| depcs-basefold-paper-protocol11 nv=19 w=2 | 970.486 -> 1058.563 | 89.419 -> 86.928 | 789.92 -> 808.05 | 797.90 -> 802.76 |
| depcs-basefold-paper-protocol11 nv=20 w=2 | 2089.836 -> 2007.132 | 356.378 -> 174.696 | 905.56 -> 910.09 | 913.74 -> 904.43 |
| depcs-basefold-paper-protocol11 nv=21 w=2 | 5371.102 -> 4231.525 | 705.427 -> 306.949 | 1022.11 -> 1026.87 | 1030.49 -> 1020.85 |
| depcs-basefold-paper-protocol11 nv=22 w=2 | 14741.211 -> 8136.030 | 1378.028 -> 627.702 | 1147.72 -> 1163.05 | 1156.30 -> 1156.68 |
| depcs-basefold-paper-protocol11 nv=23 w=2 | 36572.542 -> 18968.974 | 1285.041 -> 1210.369 | 1283.84 -> 1297.37 | 1292.63 -> 1290.63 |
| depcs-basefold-paper-protocol11 nv=24 w=2 | 113831.172 -> 73641.739 | 5525.225 -> 2595.216 | 1420.31 -> 1438.96 | 1429.30 -> 1431.87 |
| depcs-deepfold-paper-protocol11-batch nv=18 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=19 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=20 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=21 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=22 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=23 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-deepfold-paper-protocol11-batch nv=24 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=18 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=19 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=20 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=21 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=22 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=23 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
| depcs-basefold-paper-protocol11-batch nv=24 w=2 | 0.000 -> 0.000 | 0.000 -> 0.000 | 0.00 -> 0.00 | 0.00 -> n/a |
