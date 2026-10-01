// Frozen bytes are consumed without signing or rewriting fixtures.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import {
  Transaction,
  evaluate,
  decode,
  encode,
  stateBytes,
} from "./family.mjs";
import {
  Beef,
  SignedMessage,
} from "../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js";
import {
  hex,
  sha,
  preimage,
  digest,
  canonical,
} from "../../../overlays/media/0192-0199/protocol.mjs";
const read = (p) => readFileSync(new URL(p, import.meta.url));
const corpus = JSON.parse(read("./transactions.json"));
const archive = read("./" + corpus.rawArchive);
assert.equal(hex(sha(archive)), corpus.rawArchiveSHA256);
const raw = JSON.parse(gunzipSync(archive));
let accepted = 0,
  rejected = 0;
for (const c of corpus.traces) {
  const tx = Transaction.fromHex(raw[c.txid]);
  assert.equal(tx.id("hex"), c.txid);
  const results = c.sources.map((s, i) => {
    assert.equal(tx.inputs[i].sourceTXID, s.txid);
    assert.equal(tx.inputs[i].sourceOutputIndex, s.index);
    tx.inputs[i].sourceTransaction = Transaction.fromHex(raw[s.txid]);
    try {
      return evaluate(tx, i);
    } catch {
      return false;
    }
  });
  assert.equal(results.every(Boolean), c.expected === "accept", c.name);
  if (c.expected === "accept") accepted++;
  else rejected++;
}
assert.deepEqual(
  decode(encode(corpus.descriptor, corpus.state), corpus.descriptor),
  corpus.state,
);
assert.equal(stateBytes(corpus.state).length, 305);
console.log(
  JSON.stringify({
    scriptCases: accepted + rejected,
    accepted,
    rejected,
    interpreter: "@bsv/sdk 2.8.10",
    frozen: true,
  }),
);

const packageBytes = gunzipSync(read("./" + corpus.lineagePackage));
assert.equal(hex(sha(packageBytes)), corpus.lineagePackageSHA256);
const pkg = JSON.parse(packageBytes);
const checkpoint = corpus.chainCheckpoint;
const tracker = {
  isValidRootForHeight: async (root, height) =>
    root === checkpoint.txid && height === 0,
  currentHeight: async () => 101,
};
async function verifyLineage(p) {
  assert.equal(canonical(p.descriptor), canonical(corpus.descriptor));
  const sig = Buffer.from(p.genesis.signature, "base64");
  assert.equal(hex(sig.subarray(4, 37)), p.descriptor.seller);
  assert(
    SignedMessage.verify(
      [...preimage("sale-genesis", p.genesis.body)],
      [...sig],
    ),
  );
  assert.equal(p.genesis.body.listingId, digest("sale-listing", p.descriptor));
  const combined = new Beef(),
    ids = new Set();
  for (const entry of p.transactions) {
    assert(!ids.has(entry.txid));
    ids.add(entry.txid);
    const part = Beef.fromBinary([...Buffer.from(entry.beef, "base64")]);
    assert.equal(part.atomicTxid, entry.txid);
    combined.mergeBeef(part);
  }
  const seen = new Set(),
    active = new Set();
  async function visit(id, index) {
    const outpoint = id + ":" + index;
    if (seen.has(outpoint)) return;
    assert(!active.has(outpoint));
    active.add(outpoint);
    assert(ids.has(id), "missing listing path");
    const tx = Transaction.fromBEEF(combined.toBinary(), id);
    assert.equal(tx.id("hex"), id);
    assert(await tx.verify(tracker, undefined, 128 * 1024 * 1024));
    decode(tx.outputs[index].lockingScript, p.descriptor);
    if (id === p.genesis.body.genesis.txid) {
      assert.equal(index, 0);
      assert.equal(tx.inputs[0].sourceTXID, p.descriptor.lineageAnchor.txid);
      assert.equal(
        tx.inputs[0].sourceOutputIndex,
        p.descriptor.lineageAnchor.outputIndex,
      );
      assert.equal(tx.outputs[0].satoshis, Number(p.descriptor.reserve));
      assert.equal(
        tx.outputs[0].lockingScript.toHex(),
        encode(p.descriptor, p.descriptor.initialRevenue).toHex(),
      );
    } else {
      const receipt = tx.outputs.find(
        (o) =>
          o.lockingScript.toHex().startsWith("006a4c") &&
          o.lockingScript.toHex().slice(8, 16) === "524f534c",
      );
      assert(receipt, "missing transition receipt");
      const operation = receipt.lockingScript.toBinary()[9];
      const m = operation === 3 ? 2 : 1;
      for (let i = 0; i < m; i++) {
        assert(evaluate(tx, i));
        await visit(tx.inputs[i].sourceTXID, tx.inputs[i].sourceOutputIndex);
      }
    }
    active.delete(outpoint);
    seen.add(outpoint);
  }
  await visit(p.target.txid, p.target.outputIndex);
  return seen;
}
const visited = await verifyLineage(pkg);
assert.equal(visited.size, 9); // Both split outputs are distinct DAG vertices.
const missing = structuredClone(pkg);
missing.transactions = missing.transactions.filter(
  (t) => t.txid !== corpus.traces.find((t) => t.name === "left-purchase").txid,
);
await assert.rejects(() => verifyLineage(missing));
const forgedGenesis = structuredClone(pkg);
forgedGenesis.genesis.body.genesis.txid = "11".repeat(32);
await assert.rejects(() => verifyLineage(forgedGenesis));
console.log(
  JSON.stringify({
    lineageTransactions: pkg.transactions.length,
    distinctOutpoints: visited.size,
    packageBytes: packageBytes.length,
    missingParentRejected: true,
    genesisSignatureVerified: true,
  }),
);

const boundaryBytes = gunzipSync(read("./" + corpus.lineageBoundary));
assert.equal(hex(sha(boundaryBytes)), corpus.lineageBoundarySHA256);
const boundary = JSON.parse(boundaryBytes);
const copy = structuredClone(pkg);
copy.target.txid = boundary.copy.txid;
copy.transactions.push(boundary.copy);
assert.equal(
  Transaction.fromBEEF([
    ...Buffer.from(boundary.copy.beef, "base64"),
  ]).outputs[0].lockingScript.toHex(),
  encode(corpus.descriptor, corpus.state).toHex(),
);
await assert.rejects(() => verifyLineage(copy));
console.log(JSON.stringify({ copiedScriptRejectedAsLineage: true }));

const fundedMerge = Transaction.fromBEEF([
  ...Buffer.from(boundary.merge.beef, "base64"),
]);
assert(evaluate(fundedMerge, 0) && evaluate(fundedMerge, 1));
assert.equal(fundedMerge.outputs[1].lockingScript.toBinary()[9], 3);
assert.equal(
  fundedMerge.outputs[0].satoshis,
  fundedMerge.inputs[0].sourceTransaction.outputs[0].satoshis +
    fundedMerge.inputs[1].sourceTransaction.outputs[0].satoshis,
);
const claimedMerge = structuredClone(pkg);
claimedMerge.target.txid = boundary.merge.txid;
claimedMerge.transactions.push(boundary.copy, boundary.merge);
await assert.rejects(() => verifyLineage(claimedMerge));
console.log(
  JSON.stringify({
    fundedCopyMerge:
      "Script accepts real conserved value; lineage rejects unrelated history",
    noPurchaseEntitlement: true,
  }),
);
