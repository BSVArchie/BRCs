# revenue-listing-v1 executable family

The exact program is normative for the family registered by [BRC-197](../../0197.md).
This directory supplies its readable Rúnar source, reproducible build, fixed binary
metadata encoding, inverse parser, unlocking ABI and public transaction corpus.
It contains no deployed wallet or application integration.

## Reproduce

Install the common corpus's pinned Node and Python dependencies as described in
[the packet guide](../../../overlays/media/0192-0199/README.md). From the BRCs root:

```sh
node tokens/media/0197/test-family.mjs
overlays/media/0192-0199/.venv/bin/python tokens/media/0197/verify-script.py
```

Both consume the **same frozen bytes**. The independent Python check uses
BitcoinX 0.9 with post-Genesis rules, standard verification flags, 1 MiB script
limit, 128-byte Script numbers, 128 MiB stack-memory bound, one million operations
and at most eight multisig keys. The SDK check uses @bsv/sdk 2.8.10 and the same
128 MiB memory bound. These are disclosed test limits, not assertions that all
miners/wallets accept the resulting transaction size or fee policy.

To reproduce compilation, use a clean checkout of
[icellan/runar at b3f08f2](https://github.com/icellan/runar/tree/b3f08f2cc2349c311904d2c745dc19d65f23e8ca),
install that checkout's locked dependencies, and run:

```sh
RUNAR_ROOT=/absolute/path/to/runar /absolute/path/to/runar/node_modules/.bin/tsx tokens/media/0197/compile.mjs --check
```

`artifact.json` pins source, compiler output, normalization and final program hashes.
The two explicit opcode normalizations authenticate metadata through the full
scriptCode and use OP_2 OP_MUL in place of the restored OP_2MUL. The normalizer
parses opcode/push boundaries and refuses a different compiler layout. Removing a
separator does not permit replacing an arbitrary pushed byte. There are no
constructor parameters; the exact authenticated metadata prefix supplies state.

Regeneration is an explicit authoring operation: omit `--check` to write compiler
artifacts, then run `node tokens/media/0197/generate-transactions.mjs` to regenerate
the public test transactions and manifest. Re-run both oracles and update the
normative program length/hash if executable bytes changed. Never silently replace
a published family's bytes; an adopted version would require a new family IRI.

## Corpus and assurance boundary

`transactions.json` identifies each operation, expected Script outcome and failure
reason, descriptor, current initial schedule, public fixture keys, raw archive hash
and each input's source transaction/outpoint. `raw-transactions.json.gz` is a
lossless gzip JSON map from txid to complete raw hex. Compression avoids repeating
the approximately 40 KiB covenant thousands of times in the review. Both oracles
verify the archive hash, transaction IDs, exact source binding and every input's
actual execution. Nothing is fetched from the network.

The positive route graph begins with a signed authorized genesis funded from an
explicit synthetic proof-of-work checkpoint. `lineage-package.json.gz` contains
a bounded JCS package for genesis → purchase → split → both branch purchases →
merge → payout → unanimous amendment. Its partial BEEFs resolve against the other
package entries, sharing ancestors without double counting. Both implementations
check the full graph; missing parents and a valid copied-script non-descendant
are rejected as lineage. Retirement and post-amendment purchase remain separate
valid branch scenarios, not simultaneous spends of the same UTXO. The deliberately
impossible overflow source is a Script rejection test, never a claimed lineage.

`lineage-boundary.json.gz` makes the economic/provenance distinction explicit.
An independently funded identical-script copy and a seller-authorized merge of
that copy with a genuine branch pass Script, with the exact sum retained. The
full-history validator rejects that merged branch. The merge grants no purchase
entitlement and its proceeds remain constrained to the same revenue schedule;
catalogue eligibility can nevertheless be lost. This is why an administrative
client checks ancestry before asking the seller to sign. A fabricated predecessor
amount is a separate rejection case and cannot substitute imaginary value.

The common `wire-vectors.json.gz` additionally supplies successive purchases by
two buyers on one standing Offer, full LCH objects, settlement, BRC-78 grants and
authenticated AES-GCM playback. Python independently checks signatures, encodings,
BEEF bytes, transaction inputs and playback.

Negative transitions construct new preimages and re-sign changed transactions so
checks such as underpayment, payout redirection, fee extraction and missing consent
exercise route predicates. A failure caused solely by an old invalid signature is
not substituted for an economic rejection test. The corpus includes retained
remainders and externally funded exact retirement top-up.

All private scalars, CEKs, nonces and outputs are **public test material**. Funding
inputs here are signed directly with those fixture keys. BRC-100 createAction /
signAction layout preservation, multi-party wallet consent, miner policy, fee
estimation, performance and production security review remain separately required
integration qualification. This package is not a claim that those integrations or
a deployed sale service already exist.
