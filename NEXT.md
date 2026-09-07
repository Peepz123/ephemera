# Next action

> Update this file at the end of every working session. One concrete action,
> with the file and the check that proves it.

## Right now

Decide how an authenticated caller reaches a handler, and record it in
PROTOCOL.md §10.

`auth::verify_challenge` returns a `Caller`, and nothing consumes it —
`/v1/auth/verify` serialises the UUID and drops it. Every remaining endpoint
except the health checks needs to know who is calling, so this blocks
`keys::publish`, `keys::count`, blobs, and the WebSocket.

The constraint is §10: "no password, no recoverable credential." A long-lived
bearer token is a recoverable credential and contradicts that sentence. Options
worth weighing:

- Short-lived opaque token in a `token` table, returned by `/v1/auth/verify`,
  presented as a bearer header. Simple; needs a TTL short enough that §10 stays
  honest, and an expiry sweep.
- Per-request signature — sign method, path, and a timestamp with `IK_sig`.
  No stored credential at all, closest to the spirit of §10, more work on
  every client call and needs replay defence of its own.

Whichever is chosen, it lands as an axum extractor (`FromRequestParts` for
`Caller`) so handlers take `caller: Caller` and cannot forget the check.

Proven by: a request to a protected endpoint without credentials returns 401,
and the same request with them returns 200.

## Order of work

1. ~~Health endpoints answering, migrations applied~~ done
2. ~~`POST /v1/accounts` — registration~~ done
3. ~~`auth::issue_challenge` / `verify_challenge`~~ done — full round trip
   verified 2026-09-07: register 200, challenge 200, verify 200 returning the
   registered account id, replay 401, challenge for an unregistered username
   issued and 401 only at verify (T-21)
4. **Authenticated-caller carriage** — the item above
5. `POST /v1/keys/prekeys` — publication
6. `GET /v1/keys/:username` — **atomic OPK consume**, see the note in the source
7. `WS /v1/ws` — store-and-forward
8. Blobs — **atomic one-view consume**, see the note in the source

Steps 6 and 8 are the two that matter. Both are single-statement atomicity
requirements, and both fail silently if you get them wrong: no error, just a
guarantee that quietly isn't true.

## Open, small, do soon

- **Reserve `count` as a username.** `username_fmt` accepts it, and
  `/v1/keys/count` is routed before `/v1/keys/:username`, so registering that
  name makes an account permanently unreachable for bundle fetches with no
  error anywhere. Reserved-name list at registration.
- **`auth_challenges` has no sweep.** `issue_challenge` inserts a row for any
  username, unauthenticated, and only `verify_challenge` deletes. An
  unauthenticated caller can grow that table without limit. The index on
  `expires_at` is already there for it.
- **`ephemera_auth_v1` is not in PROTOCOL.md.** Every other context string is
  specified (§3.1, §3.2, §4, §5). This one exists only in `auth.rs`, which is
  why `examples/sign.rs` has to duplicate it.
- **`PUT` vs `POST` on prekeys.** §10 says `PUT /v1/keys/prekeys`; `main.rs`
  routes `post`. Pick one.
- **`opk_pub` when no OPK is available.** §3.2 says all-zero 32 bytes;
  `BundleResponse` has `Option<String>`, absent. Reconcile before writing
  `bundle` — the client parses whichever ships.
- **Conformance test 12** (map ceiling), so PROTOCOL.md §11 stops claiming
  coverage that does not exist. Pattern is in t7 and t11.
- **CI.** `cargo test`, `cargo clippy`, `cargo fmt --check`, `cargo audit`.
  T-20 commits to cargo-audit and cargo-deny as blocking checks and there is
  currently nothing behind that claim.

## Notes to self

- The server crate has no `ephemera-core` dependency, by design. If you reach
  for it, what you're writing belongs on the client.
- `git grep -n 'todo!' server/` is the progress bar.
- Async Rust is new. Expect the borrow checker to be harder here than in the
  core crate; state moved into handlers needs `Clone`, and `.await` points are
  where lifetimes get interesting.
- `CHALLENGE_TTL_SECS = 60` is too short to hand-drive with copy-paste. Script
  the round trip: capture the nonce with `ConvertFrom-Json`, call the built
  binary at `target\debug\examples\sign.exe` rather than `cargo run`, and post
  in one paste. Several 401s during the first round trip were expiry, not
  signature failure.
- Examples cannot reach a binary crate's private modules, which is why
  `sign.rs` duplicates `CTX_AUTH`. A `lib.rs` re-exporting the modules would
  fix it properly.