cargo build --release --example pip_fri --features "print-trace"

RAYON_NUM_THREADS=1 ../target/release/examples/pip_fri