#!/usr/bin/bash

trap "exit" INT TERM
trap "kill 0" EXIT

EXAMPLE_NAME=$1
NUM_PROCESSES=$2

if [ -z "$EXAMPLE_NAME" ] || [ -z "$NUM_PROCESSES" ]; then
  echo "usage: ./run_local.sh <example_name> <num_processes>"
  exit 1
fi

RUSTFLAGS='-C target-cpu=native' cargo build --release --example "$EXAMPLE_NAME"

DATA_FILE="./data/${NUM_PROCESSES}_local"
mkdir -p ./data
> "$DATA_FILE"

for ((i = 0; i < NUM_PROCESSES; i++)); do
  PORT=$((8000 + i))
  echo "127.0.0.1:$PORT" >> "$DATA_FILE"
done

BIN=../target/release/examples/$EXAMPLE_NAME
PROCS=()

# split average cores to run
for ((i = 0; i < NUM_PROCESSES / 2; i++)); do
  RAYON_NUM_THREADS=1 taskset -c "$((2 * i))" "$BIN" "$i" "$DATA_FILE" &
  PROCS+=($!)
done

for ((i = NUM_PROCESSES / 2; i < NUM_PROCESSES; i++)); do
  RAYON_NUM_THREADS=1 taskset -c "$((2 * i + 48 - NUM_PROCESSES))" "$BIN" "$i" "$DATA_FILE" &
  PROCS+=($!)
done

for pid in "${PROCS[@]}"; do
  wait "$pid"
done

echo "done"