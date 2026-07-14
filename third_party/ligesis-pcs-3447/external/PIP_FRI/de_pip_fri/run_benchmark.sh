#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <NUM_PROCESSES> <NUM_REPEATS>"
    exit 1
fi

NUM_PROCESSES=$1
NUM_REPEATS=$2

cargo build --release --bin benchmark
cargo run --release --bin benchmark -- de_pip_fri "$NUM_PROCESSES" "$NUM_REPEATS"
