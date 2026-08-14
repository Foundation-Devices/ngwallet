# Architecture FAQ

This document records properties of ngwallet that code around them takes for
granted. Read it before concluding that something is broken.

## How are remote updates bound to an account?

A `RemoteUpdate` is valid only for the account whose ID, Bitcoin network, and
SHA-256 hash of sorted descriptor strings it carries. Its sequence must be
strictly greater than the account's last accepted remote sequence, preventing
replay. Validate those bindings before applying any update.

Remote updates cannot change security-critical account metadata: account ID,
network, descriptors, preferred address type, derivation index, or multisig
configuration. They may update only the explicitly allowed cosmetic and
sync-state fields. Changes to protected metadata must use their dedicated
local API.

## Why are descriptors redacted in `Debug` output?

Descriptors may contain extended private keys. `Descriptor` therefore redacts
both descriptor fields and its persister in its `Debug` implementation, even
when a particular descriptor happens to be public. Do not weaken that behavior
or treat descriptor-bearing values as safe to log by default.

## Are private keys and mnemonics in `tests/` secrets?

No. Extended private keys and mnemonics in `tests/` are fixed, publicly known
test fixtures. They are required to exercise derivation, signing, and PSBT
validation. Do not report their presence as a production secret leak, but do
continue to treat production key material and any newly introduced real
credential as sensitive.
