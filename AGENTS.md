# ngwallet

`ngwallet` is Foundation Devices' Rust Bitcoin wallet core. It owns account
and key derivation, descriptors, PSBT construction and validation, signing,
fee handling, RBF, UTXO selection, persistence, and remote wallet updates.

## Build verification

The normal verification commands are:

```sh
just clippy
just test
```

These run Clippy and the test suite with every feature enabled, matching CI.

## Integration tests

Tests under `tests/` are conventional Rust integration-test crates. Run the
whole suite with `cargo test --all-targets --all-features` (or `just test`),
or run one integration-test crate with:

```sh
cargo test --test <test-file-stem> --all-features
```

For example, `cargo test --test psbt_multisig_security --all-features` runs
`tests/psbt_multisig_security.rs`. Do not use the multi-service test-harness
instructions from KeyOS for this repository.

## Review guidelines

`docs/automatic-code-review.md` is the review policy: scope, priorities, what
to look for, and what to leave alone. Read it in full before reviewing a PR,
along with `docs/architecture-faq.md`, which records intentional behavior that
could otherwise look like a bug.

### Posting the review

Post each finding as its own inline comment, anchored to the exact line it
concerns — one finding per comment. Use the `[Priority] Prefix: ...` format
from the policy: state the problem, then the fix, in one short paragraph.

Post exactly one top-level summary comment, and keep it to a single short
paragraph: the overall verdict, optionally with a count of findings by
priority. Do not restate the individual findings there — they live in the
inline comments. If you keep a working checklist while reviewing, edit it out
when you finish: the final summary comment must be just that one paragraph,
not the checklist.

If you find nothing to flag, post the summary comment anyway with a short
verdict (for example, "Reviewed the diff — no issues found.") rather than only
a reaction or emoji.
