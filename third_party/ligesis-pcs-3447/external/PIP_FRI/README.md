<h1 align="center">PIP<sub>FRI</sub> and DePIP<sub>FRI</sub>: Shred-to-Shine Metamorphosis of (Distributed) Polynomial Commitments </h1>

This is the Rust library for ___PIP<sub>FRI</sub>___ and ___DePIP<sub>FRI</sub>___.
PIP<sub>FRI</sub> is an efficient FRI-based multilinear polynomial commitment scheme and DePIP<sub>FRI</sub> is its distributed version.
They are preferable for efficient running times (proving and verification) and poly-log proof size.
They are also plausibly post-quantum secure in the random oracle model.

## Overview

This repository is built on the implementations of [PolyFRIM](https://github.com/guo-yanpei/PolyFRIM) (USENIX Security 2024) and [Deepfold](https://github.com/guo-yanpei/deepfold-bench) (USENIX Security 2025).
Different from their implementations, we use the `arkworks` ecosystem for finite fields and polynomial operations such as FFTs.

## Implementation details

- **Field and hash**: 
The field is $\mathbb{F}_{p}$ where $p = 2^{64} - 2^{32} + 1$, i.e., the Goldilocks field.
It is feasible to change it following the arkworks.
We use the [$\mathsf{rs}\_\mathsf{merkle}$](https://docs.rs/rs_merkle/latest/rs_merkle) package to build Merkle trees.
We use the hash function Blake3 with output size of 256 bits. 

- **FRI details**: 
The chosen code rate is $2^{-3}$.
The security level is 100 bit.
The soundness choice is the conjectured one, same as implemenations like [plonky2](https://github.com/0xPolygonZero/plonky2) and [estark](https://ia.cr/2021/582).
To modify these parameters, adjust the `SECURITY_BITS` and `CODE_RATE` in [utils](utils/src/lib.rs).
We do not use the grinding technique, also know as the proof-of-work technique.
We reduce the polynomial degree stricly by half in each round until a constant.

- **Others**: 
We currently do not provide multi-core acceleration.

## Setup

1. **Install Rust**: Follow the instructions on [Rust Installation](https://www.rust-lang.org/tools/install).
   
2. **Verify Installation**: Post-installation, ensure everything is set up correctly with:
   ```bash
   cargo --version
   rustup --version
   ```

3. **Use the Nightly Toolchain**: 
   ```bash
   rustup default nightly
   ```

## Non-Distributed PIP<sub>FRI</sub> Benchmarks
  
We provide implementations of the univariate [FRI-PCS](https://ia.cr/2019/1020) and multlinear PCSs including [Virgo](https://ia.cr/2019/1482) (S&P'20), [PolyFRIM](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-zongyang), [DeepFold](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei) and PIP<sub>FRI</sub>.
The PCSs above are all FRI-based.

We use the open-source code of [WHIR](https://github.com/WizardOfMenlo/whir).
For a fair comparison, please use unified parameters such as the code rate, the degree-reduction in each round, and the usage of grinding.
Note that its underlying FRI is approximately 2 times faster in prover and 1.2 times faster in verifier than our implemented FRI.

For group-based PCSs, please refer to the open-sourced code of [mKZG](https://github.com/EspressoSystems/hyperplonk) (PST'13) and [Hyrax](https://github.com/arkworks-rs/poly-commit)(S&P'18) for benchmarks.

To benchmark a specific PCS: Choose from `fri`, `virgo`, `polyfrim`, `deepfold` or `pip_fri`, and run
  ```bash
  cargo bench -p <a_specific_pcs>
  ```

There is an exception for Virgo.
Virgo involves two parts, a GKR sub-protocol and an IPA.
Our code above only covers the latter.
For the former GKR part, we adopt the python script from [Virgo's implementation](https://github.com/sunblaze-ucb/Virgo). 

For Virgo, we have an exception with details below, which performance 

**Benchmarking GKR**:
1. Execute `bench_gkr.py` within the `virgo/` directory.
2. This script calls the executable `virgo/fft_gkr` and produces the GKR prover time, verifier time, and proof size.

For the final evaluation result of Virgo, it is essential to sum the results from the Rust implementation and the GKR. This summation is a manual process.

### Benchmarks of SNARKs

The performance of SNARKs is from two composoble parts: PIOP and PCS.
We use the open-source code of [Spartan](https://github.com/microsoft/Spartan) and [HyperPlonk](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei) to obtain their PIOP and PCS performance, and then estimate the SNARKs' performance mannually.


## Distributed DePIP<sub>FRI</sub> Benchmarks

We provide implementations of [distributed FRI](fri/src/deprover.rs) (which serves as a sub-protocol of DePIP<sub>FRI</sub>) and [DePIP<sub>FRI</sub>](de_pip_fri/src).
The distributed network uses the [de_network](de_network/src) package.

Our open-sourced implementation provides examples in a distributed environments where each core of a single machine acts as a sub-prover (Our experiments ran on an AMD CPU with multiple cores).
This can be naturally extended to a truly distributed environment where each machine acts as a sub-prover, by changing the ip_address in the [data](de_pip_fri/data) folder.
Here, n_local means that the sub-prover number is n.
We only support the case such that n is power of two.

To run DePIP<sub>FRI</sub>, modify the `variable_num` in [de_pip_fri.rs](de_pip_fri/examples/de_pip_fri.rs).
Then, run

  ```
  cd de_pip_fri
  ./run_benchmark.sh <sub-prover number> <running times>
  ```

### Benchmarks of Other Distributed MLPCSs

For DemZKG and Dedory, we use the open-sourced code of [HyperPianist](https://github.com/AntCPLab/HyperPianist).

For DeVirgo, we estimate its performance assuming the optimal linear speedup of Virgo.
That is to say, when fixing a sub-prover number \ell and polynomial size N, we assume its prover time is 1/\ell of Virgo's prover time when its polynomial size is N.
Further, we assume the proof size and verifier time of DeVirgo are the same as those of Virgo with a polynomial size of N.

### Benchmarks of Distributed SNARKs

The performance of distributed SNARKs is from two composoble parts: distributed PIOP and distributed PCS.
We use the open-source code of HyperPianist to obtain their DePIOP and DePCS performance, and then estimate the DeSNARKs' performance mannually.
