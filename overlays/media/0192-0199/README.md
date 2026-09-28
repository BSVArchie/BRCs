# BRC-192–199 specification packet and validation

These proposals turn the application-output/private-overlay concepts into eight
separable, opt-in contracts. They are proposed specifications, not a declaration
of deployed conformance. BRC-186's conceptual discussion remains separately
reviewable in [PR #277](https://github.com/bsv-blockchain/BRCs/pull/277).

## Reading and dependency order

1. [BRC-192](../../../apps/0192.md) defines observations, evidence, assessments,
   source/store/projection ports and the shared JSON representation.
2. [BRC-193](../../0193.md) defines incremental snapshots and resumable live lookup.
3. [BRC-194](../../0194.md) defines explicit capability selection and isolated
   non-final proposal sessions.
4. [BRC-195](../../0195.md) defines protected publication and paid lookup recovery.
5. [BRC-196](../../0196.md) defines admission-linked STEAK/POTATOES delivery.
6. [BRC-197](../../../tokens/0197.md) defines listing/purchase predicates and
   optional administrative routes.
7. [BRC-198](../../../apps/0198.md) binds both acquisition paths to existing LCH.
8. [BRC-199](../../0199.md) independently defines root-host output suppression,
   local decisions and restoration.

The proposal and eviction profiles can be implemented without buying music.
The core does not require a wallet, React, MongoDB, a particular network transport
or a private seller. Application domain rules remain distinct from common ports.

## Decisions made concrete

Live v1 uses complete bounded HTTP bodies and long polling. This preserves the
current BRC-104 authenticated-body boundary while providing actual change-driven
updates and incremental database consumption. A future WebSocket/SSE/framed
profile must specify equivalent integrity, authorization and continuity; it may
reuse the same source/store contracts. Multi-host finite fan-in alone cannot claim
within-host incremental or restart-safe live conformance.

Private results use new selected routes/envelopes; old STEAK, BEEF, lookup context
and plugin interfaces remain valid. An existing interface's presence is not a
claim of durable private acquisition or subscription conformance. Unknown
required capabilities fail explicitly. Fallback needs the caller's acceptance
of the weaker guarantee.

The base covenant keeps its locking script unchanged while value increases.
Optional administration preserves aggregate listing value except explicit signed
payouts. Prices/asset/terms changes create a new lineage in v1, avoiding an
implicit rewrite of an existing buyer's agreement. Script families are explicit
compiler/artifact contracts: no arbitrary seller-provided program becomes trusted
merely by advertising a recognized predicate name. Compile-and-execute assurance
belongs to implementation qualification, and is not simulated by arithmetic.

LCH uses its own canonical CBOR IDs. The covenant Offer commits to an existing
anchor before its descriptor commits to the Offer ID, avoiding an Offer/listing
hash cycle. Covenant accumulation is a new settlement profile and cannot claim
that every artist has already received a BRC-29 payment.

Root-host eviction is separate from chain spending, global agreement and permanent
erasure. A local tombstone must fence re-admission and all serving paths before
the root reports success. Different roots can make different legitimate decisions.

## Source baseline

The implementation observations motivating the additive boundaries were checked
against TS Stack commit
[`4b9ef9764f50ae6379e0c7e06d690dae04d61d82`](https://github.com/bsv-blockchain/ts-stack/tree/4b9ef9764f50ae6379e0c7e06d690dae04d61d82):

- [`LookupService.ts`](https://github.com/bsv-blockchain/ts-stack/blob/4b9ef9764f50ae6379e0c7e06d690dae04d61d82/packages/overlays/overlay/src/LookupService.ts): finite lookup formulas, off-chain values and existing eviction callbacks.
- [`TopicManager.ts`](https://github.com/bsv-blockchain/ts-stack/blob/4b9ef9764f50ae6379e0c7e06d690dae04d61d82/packages/overlays/overlay/src/TopicManager.ts): existing optional off-chain values and dry-run context.
- [`Engine.ts`](https://github.com/bsv-blockchain/ts-stack/blob/4b9ef9764f50ae6379e0c7e06d690dae04d61d82/packages/overlays/overlay/src/Engine.ts): admission, lookup and propagation boundaries.
- [`TransactionEvidence.ts`](https://github.com/bsv-blockchain/ts-stack/blob/4b9ef9764f50ae6379e0c7e06d690dae04d61d82/packages/sdk/src/transaction/TransactionEvidence.ts): target-specific evidence and context/budget outcomes; no unspentness guarantee.
- [`persistence-v1.md`](https://github.com/bsv-blockchain/ts-stack/blob/4b9ef9764f50ae6379e0c7e06d690dae04d61d82/specs/overlay/persistence-v1.md): scoped admission operations, durable receipts and projection work; not a public retained subscription log.

Private overlay support predates this packet. The historical
[Overlay Services change](https://github.com/bsv-blockchain/overlay-services/commit/29361ad7ed24e474636488e9eb87511b8d97bf8d)
and [SDK companion](https://github.com/bsv-blockchain/ts-sdk/commit/cb86b4f1767cf4878ac8728e8871acb0b9532908)
introduced the off-chain values/lookup context pattern. BRC-81 is background,
not a substitute for inspecting those existing interfaces.

## Reproducible checks

From the repository root, with Node.js 22 or later:

```sh
node overlays/media/0192-0199/check.mjs
```

The dependency-free checker consumes [vectors.json](./vectors.json). It checks
canonical preimages/digests, integer bounds, coherent receipt/source membership,
snapshot/replay ordering, explicit capability selection, proposal compare-and-swap,
acquisition/payment idempotence, recipient isolation, covenant economic predicates,
receipt byte layout, distinct LCH bindings and independent suppression decisions.
The fixture expectations are explicit and include failures, not generated by the
same model that evaluates them. Canonical digest vectors additionally have an
independent Python check in [check.py](./check.py).

These are executable specification examples. They do **not** execute Bitcoin
Script, verify BRC-77/BEEF, prove a database's isolation, authenticate an HTTP
server or certify an application. The normative implementation conformance cases
in each BRC remain required even when these examples pass.

## Reference implementation qualification

The implementation packet must include a transport-independent core, bounded
overlay/wallet/direct adapters, durable browser storage and a second independent
store, optional UI bindings, and common behavioral fixtures. Existing evidence
verification should be reused rather than reimplemented in every adapter.

Overlay Express must provide optional source/topic companions, an actual
storage-to-batch path, transactional snapshot/replay, authenticated bounded long
polling, isolated proposals, protected publication/acquisition stores and durable
admission-linked results. Exercise both existing admission storage paths. Tests
must cover cancellation, limits, reorganization, stale work, authorization change,
crashes, cursor expiry, races and response loss. Persistence drivers and source
adapters cannot claim a guarantee their underlying systems do not provide.

Compiled covenant artifacts require reproducible versions, independent Script
execution, wallet funding and negative transition vectors before release. Every
enabled administrative route needs its own tests. LCH must exercise license/key
verification and real authenticated decryption, not merely return a key-shaped
value. Root coordination needs at least two separately configured roots and a
re-admission/restoration demonstration.

Migration guides must explain old/new clients and servers, data preservation,
selection/fallback, limits, error recovery and rollback. Compatibility tests must
cover unchanged exports, constructors, legacy routes, STEAK validators, token
formats, persisted records, browser/mobile builds and wallet permissions.

Application acceptance should include a wallet-backed task list; editable posts
with an actual live lookup subscription; federated market and music catalogues;
poll/vote transitions; several interacting social UTXO types; and encrypted
participant coordination. Content applications additionally require multi-host
examples, both acquisition mechanisms, historic entitlement/accounting migration
and playback. Product names, token mappings and rollout sequences belong in
application implementation guides rather than these protocol contracts. A
finite-only prototype is not the first usable combined release.
