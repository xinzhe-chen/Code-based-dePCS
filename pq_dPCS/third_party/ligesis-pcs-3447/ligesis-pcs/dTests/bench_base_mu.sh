#!/bin/bash
# Benchmark different base_mu values for ligesis_mu=28
# Usage: ./bench_base_mu.sh

LIGESIS_MU=28
NUM_PARTIES=4

echo "=========================================="
echo "Testing ligesis_mu=$LIGESIS_MU with different base_mu"
echo "Default base_mu = (($LIGESIS_MU - 8) / 2) + 9 = 19"
echo "=========================================="
echo ""

# Test base_mu from 15 to 21
for BASE_MU in 15 16 17 18 19 20 21; do
    echo ">>> Testing base_mu=$BASE_MU"
    python3 run.py dMultiChunkedBatchBench -n $NUM_PARTIES -m $LIGESIS_MU --trace -- --base-mu $BASE_MU 2>&1 | grep -E "(base_mu|Commit|Open|Verify|Prover total|CSV|PASS|FAIL)"
    echo ""
done
