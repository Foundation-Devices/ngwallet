# Code review guidelines

The review policy for ngwallet pull requests. Every review bot reads this
file, so it is the one place to change if the policy changes. How a review
gets posted is not here: that part differs per bot and lives with each one.

You are reviewing a PR in ngwallet, Foundation Devices' Rust Bitcoin wallet
core. It owns account and key derivation, descriptors, PSBT construction and
validation, signing, fee handling, RBF, UTXO selection, persistence, and
remote wallet updates. It depends on Foundation-maintained forks of BDK and
Foundation UR types.

Read `architecture-faq.md` before you write a single finding. It records
intentional behavior that could otherwise look like a bug.

## Related repositories

Other Foundation Devices repositories ngwallet implements, consumes, or talks
to. Consult them when a diff touches the integration surface; assume the
contract on the other side is fixed unless the PR description says otherwise.

- [`KeyOS`](https://github.com/Foundation-Devices/KeyOS) — Passport firmware.
  Its Bitcoin application depends on ngwallet directly.
- [`bdk_wallet`](https://github.com/Foundation-Devices/bdk_wallet) and
  [`bdk-1`](https://github.com/Foundation-Devices/bdk-1) — Foundation forks
  that supply the wallet, chain, Electrum, and Bitcoin primitives used here.
- [`foundation-rs`](https://github.com/Foundation-Devices/foundation-rs) —
  supplies Foundation UR types used for data interchange.

## Review scope

First, check whether you have reviewed this PR before — look for earlier
reviews or review comments you authored on it.

- If this is your first review: review the entire diff and raise every issue
  you find. Be thorough; this is the moment to surface everything about the
  existing code, because later reviews will not revisit it.
- If you have reviewed this PR before: review only what changed in the commits
  pushed since your last review, and comment only on new problems those commits
  introduce. Do not raise issues about code that was already present at your
  previous review, even if you only noticed it now, and do not restate,
  summarise, or reply to findings you raised earlier — whether or not the new
  commits resolved them. If one of your earlier findings is now genuinely fixed
  you may silently resolve its thread, but post no reply on it; leave threads
  that still stand untouched.

## How to comment

Give every finding a priority — the reviewer triages from it, and any finding
promoted to a Linear ticket inherits it:

- **Urgent** — must fix before merge: a correctness, security, or data-loss
  bug.
- **High** — should fix before merge: likely to bite, but not catastrophic.
- **Medium** — worth fixing; can be deferred to a follow-up ticket.
- **Low** — minor; nice-to-have.

Lead every inline comment with the priority in brackets, then a prefix that
signals the action expected:

- *(no prefix)* — change this, or justify why not.
- `Optional:` — an improvement; can be dismissed without justification.
- `Note:` — FYI only, no action required.

For example: `[Urgent] <problem>. <fix>.` or `[Low] Optional: <suggestion>.`
or `[Medium] Note: <observation>.`

Resolve only your own threads, and only when the code genuinely addresses them
— never resolve a comment authored by a human.

## What to look for

Urgent:

- Anything weakening key custody: seed generation or derivation, BIP32 paths,
  private descriptors, PSBT signing, key export, descriptor handling, or
  key comparison that is not constant-time.
- PSBT validation or signing changes that can spend more than the user
  approved, accept forged UTXO, script, derivation, or output metadata, change
  a recipient or fee without consent, or sign for the wrong network.
- Backup, serialization, persistence, or remote-update changes that can expose
  private keys or seed material, corrupt wallet state, or silently associate an
  update with the wrong account or descriptor set.
- Logging, panics, errors, or `Debug` implementations that can print seeds,
  mnemonics, private keys, private descriptors, PSBTs, signatures, or other
  secrets. A secret-bearing struct deriving `Debug` counts, whether or not a
  call site printing it can be pointed at; redact or sanitize the fields in a
  hand-written implementation. `Descriptor`'s existing redacted `Debug`
  implementation is intentional; see `architecture-faq.md`.
- Side-channel leaks: data-dependent branches or memory accesses in crypto
  paths, or non-constant-time comparison of secrets.

High:

- Incorrect transaction creation, fee calculation, RBF behavior, change
  output handling, address derivation, coin selection, or balance accounting.
- Missing validation or incorrect error handling on untrusted data from PSBTs,
  descriptors, backups, databases, UR payloads, or remote updates.
- Database or persistence changes that can leave wallet data inconsistent,
  unrecoverable, or associated with the wrong account after an error or
  interrupted write.
- Regression in the public API or an external integration contract without an
  intentional, documented coordinated change.

Medium:

- Latent bugs that only trigger under uncommon conditions, or error paths that
  leave a wallet unable to recover or persist future updates.
- Changes that hurt build reproducibility: embedded timestamps, absolute paths
  leaking in, or non-deterministic ordering.
- New TODOs or technical debt added without a tracking ticket.

Low:

- Typos in user-facing strings, rustdoc, or code comments.

## Do not comment on

- Formatting or style — `cargo fmt` and Clippy cover them.
- Build breakage, compiler warnings, or dead/unused code — CI runs Clippy with
  warnings denied and runs all targets and features in the test suite.
- Renames or comment rewording.
- Fixed extended private keys and mnemonics in `tests/`. They are public test
  fixtures, not production secrets; see `architecture-faq.md`.
- Speculative refactors ("you could extract this...") unless the code as
  written is wrong.
- Medium or Low findings the PR author explicitly called out in the description
  as intentional or already known.
