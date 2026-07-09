# DistZKBench Public API Quickstart

DistZKBench is a distributed benchmarking substrate. Your protocol code can live
outside this repository; it only needs to run as an adapter binary and call the
SDK or C FFI.

## Rust Adapter

```rust
fn main() -> Result<(), String> {
    let mut dzb = dzb_sdk::init()?;
    let rank = dzb.context().rank();
    let master = dzb.context().master_rank() as u32;
    let payload = dzb.context().deterministic_bytes(0, 1024);

    dzb.phase("protocol.round0", |dzb| {
        if rank == dzb.context().master_rank() {
            let _messages = dzb.gather(master, 1, &payload)?;
        } else {
            dzb.gather(master, 1, &payload)?;
        }
        Ok(())
    })?;

    if rank == dzb.context().master_rank() {
        dzb.artifacts.publish_proof_bytes(b"canonical proof bytes".to_vec())?;
    }

    dzb.finish()?;
    Ok(())
}
```

Configure it with:

```yaml
protocol:
  mode: sdk-binary
  adapter: my-protocol
  command: /absolute/path/to/my-protocol
```

The controller launches one process per rank and sets `DZB_RANK_CONFIG`.

## C FFI Adapter

Include `include/distzkbench.h` and link against `libdzb_sdk`.

```c
Dzb *dzb = dzb_init();
dzb_phase_start(dzb, "round0");
dzb_send(dzb, dst, tag, ptr, len);
DzbBuffer msg = dzb_recv(dzb, src, tag);
dzb_buf_free(msg);
dzb_phase_end(dzb);
dzb_publish_proof_bytes(dzb, proof_ptr, proof_len);
dzb_finish(dzb);
```

The C API uses opaque handles and explicit buffer ownership. Any failed call can
be diagnosed with `dzb_last_error()`.
Use `dzb_rank()`, `dzb_world_size()`, and `dzb_master_rank()` to branch protocol
logic by role.

## Toy Self-Check

Before connecting a real protocol, run:

```bash
cargo build --workspace --release --locked
./target/release/dzb run configs/examples/toy_star_4.yaml
./target/release/dzb report results/toy_star_4/<run_id>
```

The toy adapter is an external-style SDK binary (`dzb-toy-adapter`), so it tests
the same process, TCP, phase, artifact, and report path that real adapters use.
