# dePCS Bottleneck Investigation

- generated_at: 2026-06-27T01:30:22
- scope: prover time, verifier time, proof size, communication cost, and linear scalability.
- root_cause_labels: `implementation-centralized`, `backend-batching-missing`, `protocol-inherent`.

## Headline At Largest Point

| scheme | prover ms | verify ms | proof KiB | comm KiB |
| --- | ---: | ---: | ---: | ---: |
| LigeSIS dLigesis | 4130.068 | 115.111 | 290.82 | n/a |
| dFRIttata-PCS | 8683.810 | 15.149 | 1952.75 | n/a |
| dPIP-FRI-PCS | 3979.774 | 3.132 | 324.48 | n/a |
| dePCS_Basefold | 55964.308 | 19.917 | 1436.02 | 1428.93 |
| dePCS_Deepfold | 9484.122 | 14.165 | 999.29 | 991.60 |

## dePCS Vs External Ratios

| dePCS row | external row | prover | verify | proof | communication |
| --- | --- | ---: | ---: | ---: | ---: |
| dePCS_Basefold nv=18 w=2 | best at nv=18, workers=2 | 6.78x | 5.68x | 5.24x | n/a |
| dePCS_Deepfold nv=18 w=2 | best at nv=18, workers=2 | 1.92x | 4.00x | 3.37x | n/a |
| dePCS_Basefold nv=19 w=2 | best at nv=19, workers=2 | 7.01x | 4.14x | 5.06x | n/a |
| dePCS_Deepfold nv=19 w=2 | best at nv=19, workers=2 | 2.07x | 3.03x | 3.32x | n/a |
| dePCS_Basefold nv=20 w=2 | best at nv=20, workers=2 | 7.52x | 5.67x | 5.03x | n/a |
| dePCS_Deepfold nv=20 w=2 | best at nv=20, workers=2 | 2.00x | 4.13x | 3.37x | n/a |
| dePCS_Basefold nv=21 w=2 | best at nv=21, workers=2 | 7.71x | 4.77x | 4.83x | n/a |
| dePCS_Deepfold nv=21 w=2 | best at nv=21, workers=2 | 2.07x | 3.55x | 3.27x | n/a |
| dePCS_Basefold nv=22 w=2 | best at nv=22, workers=2 | 7.69x | 5.45x | 4.70x | n/a |
| dePCS_Deepfold nv=22 w=2 | best at nv=22, workers=2 | 1.99x | 3.82x | 3.23x | n/a |
| dePCS_Basefold nv=23 w=2 | best at nv=23, workers=2 | 7.81x | 7.62x | 4.83x | n/a |
| dePCS_Deepfold nv=23 w=2 | best at nv=23, workers=2 | 1.84x | 3.84x | 3.32x | n/a |
| dePCS_Basefold nv=24 w=2 | best at nv=24, workers=2 | 14.06x | 6.36x | 4.94x | n/a |
| dePCS_Deepfold nv=24 w=2 | best at nv=24, workers=2 | 2.38x | 4.52x | 3.44x | n/a |

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
| depcs-basefold-paper-protocol11 | 18 | 2 | 3.94 | 695.36 | 704.24 | 0.9 | 0.9 | 65.0 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 4.04 | 795.72 | 805.05 | 0.8 | 0.8 | 65.2 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 4.13 | 912.61 | 922.40 | 0.8 | 0.8 | 65.3 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 4.22 | 1029.41 | 1039.65 | 0.7 | 0.7 | 65.4 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 4.32 | 1146.41 | 1157.10 | 0.7 | 0.7 | 65.5 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 4.41 | 1290.08 | 1301.23 | 0.6 | 0.6 | 65.6 | 0.0 | 16 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 4.50 | 1424.43 | 1436.02 | 0.6 | 0.6 | 65.7 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 3.64 | 443.66 | 452.84 | 1.4 | 1.4 | 64.2 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 3.74 | 518.55 | 528.18 | 1.3 | 1.3 | 64.4 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 3.83 | 606.66 | 616.74 | 1.1 | 1.1 | 64.7 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 3.93 | 693.82 | 704.35 | 1.0 | 1.0 | 64.9 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 4.02 | 784.24 | 795.23 | 1.0 | 1.0 | 65.0 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 4.11 | 883.79 | 895.23 | 0.9 | 0.9 | 65.1 | 0.0 | 16 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 4.21 | 987.39 | 999.29 | 0.8 | 0.8 | 65.3 | 0.0 | 16 |

## Paper Artifact Timing Breakdown

| scheme | nv | workers | wall commit | worker commit max | worker commit sum | wall open | worker open max | worker open sum | master assemble | wall verify | worker verify max | worker verify sum | master verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| depcs-basefold-paper-protocol11 | 18 | 2 | 309.659 | 308.836 | 608.732 | 173.313 | 166.936 | 332.501 | 5.051 | 8.756 | 3.379 | 6.740 | 8.752 |
| depcs-basefold-paper-protocol11 | 19 | 2 | 614.319 | 613.954 | 1220.960 | 337.712 | 330.842 | 660.218 | 5.784 | 9.703 | 3.867 | 7.569 | 9.699 |
| depcs-basefold-paper-protocol11 | 20 | 2 | 1292.524 | 1292.131 | 2564.806 | 655.273 | 647.859 | 1283.232 | 6.341 | 11.185 | 4.446 | 8.623 | 11.182 |
| depcs-basefold-paper-protocol11 | 21 | 2 | 2664.341 | 2664.007 | 5327.693 | 1300.454 | 1291.871 | 2569.422 | 6.717 | 11.933 | 4.859 | 9.704 | 11.930 |
| depcs-basefold-paper-protocol11 | 22 | 2 | 5371.472 | 5371.186 | 10732.593 | 2688.293 | 2678.120 | 5328.549 | 8.059 | 13.766 | 5.441 | 10.556 | 13.763 |
| depcs-basefold-paper-protocol11 | 23 | 2 | 11882.432 | 11882.049 | 23646.599 | 6096.152 | 6086.221 | 12093.490 | 8.398 | 21.846 | 12.485 | 19.333 | 21.843 |
| depcs-basefold-paper-protocol11 | 24 | 2 | 32556.982 | 32555.875 | 62282.684 | 23407.326 | 23394.219 | 46013.299 | 9.272 | 19.917 | 8.794 | 17.396 | 19.912 |
| depcs-deepfold-paper-protocol11 | 18 | 2 | 71.180 | 70.927 | 141.169 | 65.870 | 62.165 | 123.684 | 3.146 | 6.166 | 2.683 | 5.171 | 6.164 |
| depcs-deepfold-paper-protocol11 | 19 | 2 | 161.979 | 161.539 | 317.553 | 119.446 | 114.725 | 226.573 | 3.492 | 7.108 | 3.256 | 6.425 | 7.105 |
| depcs-deepfold-paper-protocol11 | 20 | 2 | 305.791 | 305.557 | 608.494 | 211.953 | 206.515 | 410.733 | 4.633 | 8.136 | 3.708 | 7.304 | 8.134 |
| depcs-deepfold-paper-protocol11 | 21 | 2 | 645.730 | 645.235 | 1268.190 | 416.164 | 410.573 | 817.758 | 4.727 | 8.889 | 3.897 | 7.461 | 8.886 |
| depcs-deepfold-paper-protocol11 | 22 | 2 | 1294.165 | 1293.286 | 2564.514 | 786.452 | 779.451 | 1549.058 | 5.346 | 9.655 | 3.993 | 7.983 | 9.652 |
| depcs-deepfold-paper-protocol11 | 23 | 2 | 2667.271 | 2666.979 | 5324.971 | 1576.695 | 1569.073 | 3127.810 | 6.038 | 11.015 | 4.734 | 9.208 | 11.013 |
| depcs-deepfold-paper-protocol11 | 24 | 2 | 6181.860 | 6181.514 | 12257.493 | 3302.261 | 3294.151 | 6542.779 | 6.733 | 14.165 | 6.893 | 12.329 | 14.163 |

## Scheme Differences

- dePCS proves a Brakedown-style Protocol 11 evaluation plus two Protocol 10 encoding relations over independent per-worker transparent PC commitments.
- LigeSIS uses SIS hashing plus DeepFold multi-chunked batch openings and extension-field sumchecks, which keeps verifier-facing proof size small but can send more network data at high party counts.
- dFRIttata follows a FRI fold-and-batch path and avoids dePCS Protocol 10/11 encoding consistency proof shape.
- dPIP-FRI is a specialized distributed PIP-FRI path; it has much smaller proof/verifier/communication constants but is not the same dePCS Brakedown protocol.
