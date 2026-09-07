# Next action

> Update this file at the end of every working session. One concrete action,
> with the file and the check that proves it.

## Right now

Implement `register` in `server/src/routes/accounts.rs`.
Decode the three base64 fields, verify ik_dh_sig over
"ephemera_ikdh_v1" || ik_dh, insert.
Duplicate username must return 409, not 500 —
sqlx::Error::Database(e) with e.is_unique_violation().
Proven by: curl a registration, then curl the same one again.
Reference: PROTOCOL.md 3.1.

## Order of work

1. Health endpoints answering, migrations applied
2. `POST /v1/accounts` — registration
3. `auth::issue_challenge` / `verify_challenge`
4. `POST /v1/keys/prekeys` — publication
5. `GET /v1/keys/:username` — **atomic OPK consume**, see the note in the source
6. `WS /v1/ws` — store-and-forward
7. Blobs — **atomic one-view consume**, see the note in the source

Steps 5 and 7 are the two that matter. Both are single-statement atomicity
requirements, and both fail silently if you get them wrong: no error, just a
guarantee that quietly isn't true.

## Notes to self

- The server crate has no `ephemera-core` dependency, by design. If you reach
  for it, what you're writing belongs on the client.
- `git grep -n 'todo!' server/` is the progress bar.
- Async Rust is new. Expect the borrow checker to be harder here than in the
  core crate; state moved into handlers needs `Clone`, and `.await` points are
  where lifetimes get interesting.
