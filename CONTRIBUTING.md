# Contributing to ALICE-Auth

## Build

```bash
cargo build
cargo build --no-default-features   # no_std check (default)
cargo build --features std           # std build
```

## Test

```bash
cargo test --features std                        # core tests
cargo test --features "std,api,db"               # + API/DB bridges
cargo test --features "std,api,db,nizk"          # + Schnorr NIZK (all features)
```

> **Note**: The `std` feature is required for testing because the test harness
> needs panic unwinding. The `nizk` feature requires `alice-crypto` and `curve25519-dalek`.

## Lint

```bash
cargo clippy --features "std,api,db,nizk" -- -W clippy::all
cargo fmt -- --check
cargo doc --features "std,api,db,nizk" --no-deps 2>&1 | grep warning
```

## Design Constraints

- **no_std core**: default build is `no_std` with zero allocations. Use `alloc` or `std` features for heap types.
- **No loops**: hex encoding and hot paths are fully unrolled at compile time.
- **No branches in release**: `#[cold]` error paths, branchless success paths.
- **Fixed-size types**: `AliceId` = 32 bytes, `AliceSig` = 64 bytes, `Pending` = 64 bytes — all `repr(transparent)` or `repr(C)`.
- **Zero .rodata in release**: `Display` / `Debug` impls emit nothing when `debug_assertions` is off.
