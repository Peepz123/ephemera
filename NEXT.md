# Next action

> Update this file at the end of every working session. One concrete action,
> with the file and the test that proves it. Not "continue the ratchet".

## Right now

**Implement `x3dh::initiate` in `crates/ephemera-core/src/x3dh.rs`.**

- Checklist is in the doc comment above the function.
- Proven by: `cargo test --test conformance t3_`
- Reference: `docs/PROTOCOL.md` section 4.
- `agree()` and `derive_sk()` in the same module are already written — you need
  the four DH calls in the right order and the concatenation behind `F_PREFIX`.

## Order of work

1. `x3dh::initiate` + `x3dh::respond` → t3, t3b
2. `SessionState::initiator` / `responder` → unblocks everything else
3. `SessionState::encrypt` → t4 (partially)
4. `SessionState::decrypt`, in-order path → t4
5. Skipped-key storage → t5, t6
6. Skip cap, atomically → t7
7. Skipped-key deletion on use → t8
8. Confirm AD covers the header → t9, t10 should pass without new code

Steps 5 to 8 are where ratchet implementations break. Do not rush them.

## State of the suite

    cargo test              # 24 passing, 9 failing — the 9 are the work
    cargo test --test conformance   # just the failing ones

## Notes to self

- Every `#[allow(unused_variables)]` in the source is a marker for unimplemented
  code. When the last one is gone, Phase 1 is done.
- `git grep -n 'todo!'` is the other progress bar.
