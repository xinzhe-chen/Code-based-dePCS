cargo build --release --example batch_fri --no-default-features --features "print-trace"

RAYON_NUM_THREADS=1 ../target/release/examples/batch_fri