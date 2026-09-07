# Next action

> Update this file at the end of every working session. One concrete action,
> with the file and the check that proves it.

## Right now

Write `server/migrations/0002_auth_tokens.sql`.

Decision made 2026-09-07: short-lived opaque session token, specified in
PROTOCOL.md §10.2. §10 was reworded and the correction recorded in
THREAT-MODEL.md §12.

The table has to carry what §10.2 commits to: a 32-byte token stored as a
SHA-256 hash, scoped to exactly one account, expiring 15 minutes from issue,
deleted on lookup when expired and swept periodically.

Open questions to settle while writing it:

- Primary key — the hash is unique and unguessable, which suggests one answer.
  But is there ever a need to look up tokens *by account*, to invalidate all
  sessions on identity change? That changes what gets indexed.
- Store `account_id` directly rather than `username`. The account id is known
  at issue time, and a foreign key gets `ON DELETE CASCADE`, which
  `auth_challenges` does not have.
- `CHECK (octet_length(...) = 32)` on the hash, matching the convention in
  `0001_init.sql`.
- Which column does the sweep need an index on?

Proven by: `cargo run -p ephemera-server` applies the migration cleanly on
startup.

Then `auth::issue_token` / `verify_token`, then `/v1/auth/verify` returning a
token, then `impl FromRequestParts for Caller`, then `caller: Caller` on
`keys::publish` — proven by a 401 without credentials and a 200 with them.

## Order of work

1. ~~Health endpoints answering, migrations applied~~ done
2. ~~`POST /v1/accounts` — registration~~ done
3. ~~`auth::issue_challenge` / `verify_challenge`~~ done — full round trip
   verified 2026-09-07: register 200, challenge 200, verify 200 returning the
   registered account id, replay 401, challenge for an unregistered username
   issued and 401 only at verify (T-21)
4. ~~Authenticated-caller carriage — decision~~ done: short-lived opaque
   token, PROTOCOL.md §10.2
5. Token table, `Caller` extractor
6. `POST /v1/keys/prekeys` — publication
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
- **WebSocket token lifetime is unresolved.** A 15-minute token against a
  connection that may stay open for hours: checked only at connect, or
  re-checked during the connection's life? If only at connect, the effective
  bound on relay access is the connection lifetime, and PROTOCOL.md §10.2
  overstates its guarantee. Settle before writing `routes::ws::handler`.

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
  - Session tokens are hashed at rest, so `verify_token` hashes the presented
  token and looks up by hash. There is no way to recover a token from the
  table, which is the point.