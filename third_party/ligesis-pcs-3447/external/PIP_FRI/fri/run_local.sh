#!/usr/bin/bash

trap "exit" INT TERM
trap "kill 0" EXIT

EXAMPLE_NAME=$1
NUM_PROCESSES=$2
# cargo build --release --example $1 --no-default-features --features "print-trace"
## Below is the true command for distributed environment
# RAYON_NUM_THREADS=4 cargo build --release --example $1 --no-default-features --features "parallel print-trace"
# RAYON_NUM_THREADS=32 RUSTFLAGS="-C target-cpu=native -C target-feature=+bmi2,+adx" cargo build --release --example de_biv_batch_kzg --no-default-features --features "parallel asm" 
# RAYON_NUM_THREADS=32 RUSTFLAGS="-C target-cpu=native -C target-feature=+bmi2,+adx" cargo build --release --example de_biv_batch_kzg_same_point --no-default-features --features "parallel asm" 
# BIN=../target/release/examples/$1

if [ -z "$EXAMPLE_NAME" ] || [ -z "$NUM_PROCESSES" ]; then
  echo "usage: ./run_local.sh <example_name> <num_processes>"
  exit 1
fi

RUSTFLAGS='-C target-cpu=native' cargo build --release --example "$EXAMPLE_NAME" --no-default-features
# --features "print-trace"

DATA_FILE="./data/${NUM_PROCESSES}_local"
mkdir -p ./data
> "$DATA_FILE"

for ((i = 0; i < NUM_PROCESSES; i++)); do
  PORT=$((8000 + i))
  echo "127.0.0.1:$PORT" >> "$DATA_FILE"
done

BIN=../target/release/examples/$EXAMPLE_NAME
PROCS=()

for ((i = 0; i < NUM_PROCESSES; i++)); do
  RAYON_NUM_THREADS=1 taskset -c "$((i * 2))" "$BIN" "$i" "$DATA_FILE" &
  PROCS+=($!)
done

for pid in "${PROCS[@]}"; do
  wait "$pid"
done

echo "done"