import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import {
  MerklePath,
  SignedMessage,
} from "../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js";
import {
  Transaction,
  LockingScript,
  UnlockingScript,
  PrivateKey,
  P2PKH,
  Hash,
  pub,
  pkh,
  ys,
  le,
  encode,
  stateBytes,
  output,
  payoutOutputs,
  adminReceipt,
  serializeOutput,
  unlock,
  evaluate,
} from "./family.mjs";
import {
  digest,
  purchaseReceipt,
  hex,
  sha,
  hash256,
  b64,
  preimage,
  canonical,
} from "../../../overlays/media/0192-0199/protocol.mjs";
const seller = new PrivateKey(41),
  a = new PrivateKey(42),
  b = new PrivateKey(43),
  buyer = new PrivateKey(44);
const identities = [a, b].sort((x, y) => pub(x).localeCompare(pub(y)));
const state = {
  revision: "0",
  recipients: identities.map((k, i) => ({
    identity: pub(k),
    weight: i ? 3 : 7,
  })),
};
const descriptor = {
  version: 1,
  chain: { network: "fixture", genesisHash: "00".repeat(32) },
  assetId: "11".repeat(32),
  seller: pub(seller),
  lineageAnchor: {
    chain: { network: "fixture", genesisHash: "00".repeat(32) },
    txid: "22".repeat(32),
    outputIndex: 0,
  },
  purchasePrice: "1001",
  reserve: "1",
  termsDigest: "33".repeat(32),
  scriptFamily: "https://bsv.brc.dev/tokens/0197#revenue-listing-v1",
  administration: "seller-v1",
  metadataDigest: "44".repeat(32),
  initialRevenue: state,
};
// One explicit synthetic proof-of-work checkpoint funds the entire route DAG.
const root = new Transaction(
  1,
  [
    {
      sourceTXID: "00".repeat(32),
      sourceOutputIndex: 0xffffffff,
      unlockingScript: UnlockingScript.fromHex("020101"),
      sequence: 0xffffffff,
    },
  ],
  Array.from({ length: 64 }, (_, i) =>
    output(100100, new P2PKH().lock([...pkh(i === 0 ? seller : buyer)])),
  ),
  0,
);
const header = Buffer.alloc(80);
header.writeUInt32LE(1);
Buffer.from(root.id("hex"), "hex").reverse().copy(header, 36);
header.writeUInt32LE(1790611200, 68);
header.writeUInt32LE(0x207fffff, 72);
let nonce = 0;
while (true) {
  header.writeUInt32LE(nonce++, 76);
  if (
    BigInt("0x" + hex(Buffer.from(hash256(header)).reverse())) <=
    0x7fffffn << 232n
  )
    break;
}
const chain = {
  network: "brc-family-fixture-easy-work",
  genesisHash: hex(Buffer.from(hash256(header)).reverse()),
};
root.merklePath = new MerklePath(0, [
  [{ offset: 0, hash: root.id("hex"), txid: true }],
]);
descriptor.chain = chain;
descriptor.lineageAnchor = { chain, txid: root.id("hex"), outputIndex: 0 };
let nextFunding = 1;
const all = new Map([[root.id("hex"), root]]);
const seed = async (script, value) => {
  const tx = new Transaction(
    1,
    [
      {
        sourceTransaction: root,
        sourceTXID: root.id("hex"),
        sourceOutputIndex: nextFunding++,
        sequence: 0xffffffff,
        unlockingScript: UnlockingScript.fromHex(""),
      },
    ],
    [output(value, script)],
    0,
  );
  tx.inputs[0].unlockingScript = await new P2PKH().unlock(buyer).sign(tx, 0);
  all.set(tx.id("hex"), tx);
  return tx;
};
const input = (tx, index = 0) => ({
  sourceTransaction: tx,
  sourceTXID: tx.id("hex"),
  sourceOutputIndex: index,
  sequence: 0xffffffff,
  unlockingScript: UnlockingScript.fromHex(""),
});
const traces = [];
async function build(label, parents, operation, options = {}) {
  const current = parents.map(([tx, i = 0]) => tx.outputs[i]),
    sum = current.reduce((n, o) => n + BigInt(o.satoshis), 0n);
  const st = options.state ?? state,
    script = current[0].lockingScript;
  let outputs = [],
    receipt,
    payments = [],
    payout = 0n,
    m = parents.length,
    n = 1;
  if (operation === 1) {
    outputs = [output(sum + 1001n, script)];
    receipt = LockingScript.fromHex(
      hex(
        purchaseReceipt(
          {
            listingId: digest("sale-listing", descriptor),
            termsDigest: descriptor.termsDigest,
          },
          "55".repeat(32),
          "66".repeat(32),
          pub(buyer),
        ),
      ),
    );
  }
  if (operation === 2) {
    n = 2;
    outputs = [
      output(options.splitAmount, script),
      output(sum - BigInt(options.splitAmount), script),
    ];
  }
  if (operation === 3) {
    outputs = [output(sum, script)];
  }
  if (operation === 4 || operation === 5) {
    const total = st.recipients.reduce((v, r) => v + BigInt(r.weight), 0n);
    const units =
      operation === 4
        ? BigInt(options.payoutUnits)
        : (sum + total - 1n) / total;
    payout = units * total;
    payments = payoutOutputs(st, units);
    if (operation === 4) outputs = [output(sum - payout, script)];
    else n = 0;
  }
  if (operation === 6) {
    outputs = [output(sum, encode(descriptor, options.newState))];
  }
  if (operation !== 1)
    receipt = adminReceipt(
      descriptor,
      operation,
      m,
      n,
      payout,
      operation === 6
        ? sha(stateBytes(options.newState))
        : payments.length
          ? sha(Buffer.concat(payments.map(serializeOutput)))
          : Buffer.alloc(32),
    );
  outputs.push(output(1, receipt), ...payments);
  const funding = await seed(new P2PKH().lock([...pkh(buyer)]), 100000);
  const tx = new Transaction(
    1,
    [...parents.map(([t, i]) => input(t, i)), input(funding)],
    outputs,
    0,
  );
  const change = Number(
    sum + 100000n - outputs.reduce((v, o) => v + BigInt(o.satoshis), 0n) - 100n,
  );
  tx.addOutput(output(change, new P2PKH().lock([...pkh(buyer)])));
  const args = {
    operation,
    receipt,
    recipientY: operation === 1 ? ys(buyer) : undefined,
    splitAmount: options.splitAmount,
    payoutUnits: options.payoutUnits,
    adminKey: operation === 1 ? undefined : seller,
    newState: options.newState,
    newKeyYs: options.newState
      ? Buffer.concat([
          ...options.newKeys.map(ys),
          Buffer.alloc((8 - options.newKeys.length) * 32),
        ])
      : undefined,
    consentKeys: operation === 6 ? identities : undefined,
    changeHash: pkh(buyer),
    changeAmount: change,
  };
  if (options.mutate) options.mutate(tx);
  if (options.mutateArgs) options.mutateArgs(args, tx);
  for (let i = 0; i < parents.length; i++) {
    tx.inputs[i].unlockingScript = unlock(tx, i, {
      ...args,
      otherPrevious:
        operation === 3
          ? (args.otherPrevious ?? Buffer.from(parents[1 - i][0].toBinary()))
          : undefined,
    });
  }
  if (options.mutateUnlock) options.mutateUnlock(tx);
  tx.inputs.at(-1).unlockingScript = await new P2PKH()
    .unlock(buyer)
    .sign(tx, tx.inputs.length - 1);
  const outcomes = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    try {
      outcomes.push(evaluate(tx, i));
    } catch (e) {
      outcomes.push(false);
    }
  }
  const expected = options.expected ?? "accept";
  assert.equal(
    outcomes.every(Boolean),
    expected === "accept",
    label + " " + JSON.stringify(outcomes),
  );
  traces.push({
    name: label,
    operation,
    raw: tx.toHex(),
    sources: tx.inputs.map((i) => ({
      raw: i.sourceTransaction.toHex(),
      index: i.sourceOutputIndex,
    })),
    expected,
    layer: "script",
    reason: options.reason ?? "valid-transition",
  });
  all.set(tx.id("hex"), tx);
  console.log(label, expected, tx.toBinary().length);
  return tx;
}
const genesis = new Transaction(
  1,
  [input(root, 0)],
  [
    output(1, encode(descriptor, state)),
    output(99999, new P2PKH().lock([...pkh(seller)])),
  ],
  0,
);
genesis.inputs[0].unlockingScript = await new P2PKH()
  .unlock(seller)
  .sign(genesis, 0);
all.set(genesis.id("hex"), genesis);
const genesisBody = {
  version: 1,
  listingId: digest("sale-listing", descriptor),
  genesis: { chain, txid: genesis.id("hex"), outputIndex: 0 },
};
const genesisAuthorization = {
  body: genesisBody,
  signature: b64(
    SignedMessage.sign([...preimage("sale-genesis", genesisBody)], seller),
  ),
};
const p1 = await build("purchase", [[genesis, 0]], 1);
const split = await build("split", [[p1, 0]], 2, { splitAmount: 500 });
const p2 = await build("left-purchase", [[split, 0]], 1);
const p3 = await build("right-purchase", [[split, 1]], 1);
const merge = await build(
  "merge",
  [
    [p2, 0],
    [p3, 0],
  ],
  3,
);
const payout = await build("payout", [[merge, 0]], 4, { payoutUnits: 100 });
const newKeys = [new PrivateKey(45), new PrivateKey(46)].sort((x, y) =>
  pub(x).localeCompare(pub(y)),
);
const nextState = {
  revision: "1",
  recipients: newKeys.map((k, i) => ({ identity: pub(k), weight: i ? 1 : 1 })),
};
const amend = await build("amend-all-consent", [[payout, 0]], 6, {
  newState: nextState,
  newKeys,
});
await build("retire", [[amend, 0]], 5, { state: nextState });

await build("retire-topup-six-satoshis", [[payout, 0]], 5);
const reject = (reason, rest = {}) => ({ expected: "reject", reason, ...rest });
await build(
  "reject-purchase-under-increment",
  [[genesis, 0]],
  1,
  reject("successor-value", { mutate: (t) => t.outputs[0].satoshis-- }),
);
await build(
  "reject-purchase-over-increment",
  [[genesis, 0]],
  1,
  reject("successor-value", { mutate: (t) => t.outputs[0].satoshis++ }),
);
await build(
  "reject-purchase-changed-script",
  [[genesis, 0]],
  1,
  reject("successor-script", {
    mutate: (t) =>
      (t.outputs[0].lockingScript = new P2PKH().lock([...pkh(buyer)])),
  }),
);
await build(
  "reject-zero-receipt",
  [[genesis, 0]],
  1,
  reject("receipt-value", { mutate: (t) => (t.outputs[1].satoshis = 0) }),
);
await build(
  "reject-extra-output",
  [[genesis, 0]],
  1,
  reject("output-layout", {
    mutate: (t) => t.addOutput(output(1, new P2PKH().lock([...pkh(buyer)]))),
  }),
);
await build(
  "reject-locktime",
  [[genesis, 0]],
  1,
  reject("locktime", { mutate: (t) => (t.lockTime = 1) }),
);
await build(
  "reject-nonfinal-funding",
  [[genesis, 0]],
  1,
  reject("sequence", { mutate: (t) => (t.inputs[1].sequence = 0xfffffffe) }),
);
await build(
  "reject-price-overflow",
  [[await seed(encode(descriptor, state), 2100000000000000), 0]],
  1,
  reject("satoshi-overflow"),
);
await build(
  "reject-split-reserve",
  [[p1, 0]],
  2,
  reject("reserve", { splitAmount: 0 }),
);
await build(
  "reject-split-drain",
  [[p1, 0]],
  2,
  reject("split-conservation", {
    splitAmount: 500,
    mutate: (t) => {
      t.outputs[0].satoshis--;
      t.outputs.at(-1).satoshis++;
    },
  }),
);
await build(
  "reject-forged-merge-parent",
  [
    [p2, 0],
    [p3, 0],
  ],
  3,
  reject("parent-hash", {
    mutateArgs: (x) => (x.otherPrevious = Buffer.from([0])),
  }),
);
await build(
  "reject-payout-redirect",
  [[merge, 0]],
  4,
  reject("payout-destination", {
    payoutUnits: 100,
    mutate: (t) =>
      (t.outputs[2].lockingScript = new P2PKH().lock([...pkh(buyer)])),
  }),
);
await build(
  "reject-payout-shares",
  [[merge, 0]],
  4,
  reject("payout-shares", {
    payoutUnits: 100,
    mutate: (t) => {
      t.outputs[2].satoshis--;
      t.outputs[3].satoshis++;
    },
  }),
);
await build(
  "reject-payout-reserve",
  [[merge, 0]],
  4,
  reject("reserve", { payoutUnits: 301 }),
);
await build(
  "reject-admin-authority",
  [[merge, 0]],
  4,
  reject("seller-signature", {
    payoutUnits: 100,
    mutateArgs: (x) => (x.adminKey = buyer),
  }),
);
await build(
  "reject-missing-consent",
  [[payout, 0]],
  6,
  reject("recipient-consent", {
    newState: nextState,
    newKeys,
    mutateArgs: (x) => (x.consentKeys = [identities[0]]),
  }),
);
await build(
  "reject-wrong-consent",
  [[payout, 0]],
  6,
  reject("recipient-consent", {
    newState: nextState,
    newKeys,
    mutateArgs: (x) => (x.consentKeys = [identities[0], buyer]),
  }),
);
await build(
  "reject-revision-skip",
  [[payout, 0]],
  6,
  reject("revenue-revision", {
    newState: { ...nextState, revision: "2" },
    newKeys,
  }),
);
await build(
  "reject-amend-drain",
  [[payout, 0]],
  6,
  reject("amend-conservation", {
    newState: nextState,
    newKeys,
    mutate: (t) => t.outputs[0].satoshis--,
  }),
);
await build(
  "reject-retire-share-theft",
  [[payout, 0]],
  5,
  reject("retirement-shares", {
    mutate: (t) => {
      t.outputs[1].satoshis--;
      t.outputs[2].satoshis++;
    },
  }),
);
const changeReceipt = (offset, bytes) => (args, tx) => {
  const raw = Buffer.from(args.receipt.toBinary());
  Buffer.from(bytes).copy(raw, offset);
  args.receipt = LockingScript.fromHex(hex(raw));
  tx.outputs[1].lockingScript = args.receipt;
};
await build(
  "reject-receipt-listing-id",
  [[genesis, 0]],
  1,
  reject("receipt-listing-id", {
    mutateArgs: changeReceipt(10, Buffer.alloc(32, 1)),
  }),
);
await build(
  "reject-receipt-terms",
  [[genesis, 0]],
  1,
  reject("receipt-terms", {
    mutateArgs: changeReceipt(139, Buffer.alloc(32, 1)),
  }),
);
await build(
  "reject-recipient-curve",
  [[genesis, 0]],
  1,
  reject("recipient-point", {
    mutateArgs: changeReceipt(
      106,
      Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 255)]),
    ),
  }),
);
await build("purchase-other-valid-recipient", [[genesis, 0]], 1, {
  mutateArgs: (args, tx) => {
    changeReceipt(106, Buffer.from(pub(a), "hex"))(args, tx);
    args.recipientY = ys(a);
  },
  reason:
    "Script-valid; prepared recipient still requires separate domain check",
});
await build(
  "reject-false-preimage",
  [[genesis, 0]],
  1,
  reject("authenticated-preimage", {
    mutateUnlock: (tx) => {
      tx.inputs[0].unlockingScript.chunks[0].data[120] ^= 1;
    },
  }),
);
await build(
  "reject-truncated-prevouts",
  [[genesis, 0]],
  1,
  reject("complete-prevouts", {
    mutateUnlock: (tx) => {
      tx.inputs[0].unlockingScript.chunks[1].data.pop();
    },
  }),
);
await build(
  "reject-unknown-operation",
  [[genesis, 0]],
  1,
  reject("route-exclusivity", { mutateArgs: (args) => (args.operation = 7) }),
);
await build(
  "reject-merge-without-other-input",
  [[p2, 0]],
  3,
  reject("merge-input-count", {
    mutateArgs: (args) => (args.otherPrevious = Buffer.from(p3.toBinary())),
  }),
);
await build(
  "reject-zero-payout",
  [[merge, 0]],
  4,
  reject("positive-payout", { payoutUnits: 0 }),
);
await build(
  "reject-seller-only-amendment",
  [[payout, 0]],
  6,
  reject("all-current-recipients", {
    newState: nextState,
    newKeys,
    mutateArgs: (args) => (args.consentKeys = []),
  }),
);
await build(
  "reject-retire-with-missing-topup",
  [[payout, 0]],
  5,
  reject("exact-retirement-total", {
    mutate: (tx) => (tx.outputs[1].satoshis -= 6),
  }),
);
await build("purchase-after-amendment", [[amend, 0]], 1);

const copied = new Transaction(
  1,
  [input(root, 63)],
  [
    output(1, encode(descriptor, state)),
    output(99999, new P2PKH().lock([...pkh(buyer)])),
  ],
  0,
);
copied.inputs[0].unlockingScript = await new P2PKH()
  .unlock(buyer)
  .sign(copied, 0);
all.set(copied.id("hex"), copied);
const fundedCopyMerge = await build(
  "merge-funded-copy-conserves-value",
  [
    [payout, 0],
    [copied, 0],
  ],
  3,
  {
    reason:
      "Script-valid real-value contribution; domain rejects unrelated genesis history",
  },
);
const boundary = {
  copy: { txid: copied.id("hex"), beef: b64(copied.toAtomicBEEF()) },
  merge: {
    txid: fundedCopyMerge.id("hex"),
    beef: b64(fundedCopyMerge.toAtomicBEEF()),
  },
  genuinePrevious: { txid: payout.id("hex"), outputIndex: 0 },
};
const boundaryBytes = Buffer.from(JSON.stringify(boundary));
writeFileSync(
  new URL("./lineage-boundary.json.gz", import.meta.url),
  gzipSync(boundaryBytes, { level: 9 }),
);
const listingTxs = [genesis, p1, split, p2, p3, merge, payout, amend];
const packageBody = {
  version: 1,
  descriptor,
  genesis: genesisAuthorization,
  target: { chain, txid: amend.id("hex"), outputIndex: 0 },
  transactions: listingTxs
    .map((tx) => {
      const partial = Transaction.fromHex(tx.toHex());
      partial.inputs.forEach((i, index) => {
        const parent = tx.inputs[index].sourceTransaction;
        if (!listingTxs.includes(parent)) i.sourceTransaction = parent;
      });
      return { txid: tx.id("hex"), beef: b64(partial.toAtomicBEEF(true)) };
    })
    .sort((a, b) => (a.txid < b.txid ? -1 : 1)),
};
assert(Buffer.byteLength(canonical(packageBody)) <= 2097152);
writeFileSync(
  new URL("./lineage-package.json.gz", import.meta.url),
  gzipSync(Buffer.from(canonical(packageBody)), { level: 9 }),
);
const rawTransactions = Object.fromEntries(
  [...all].map(([id, tx]) => [id, tx.toHex()]),
);
for (const t of traces) {
  const tx = Transaction.fromHex(t.raw);
  rawTransactions[tx.id("hex")] = t.raw;
  t.txid = tx.id("hex");
  delete t.raw;
  t.sources = t.sources.map((s) => {
    const previous = Transaction.fromHex(s.raw);
    rawTransactions[previous.id("hex")] = s.raw;
    return { txid: previous.id("hex"), index: s.index };
  });
}
const compressed = gzipSync(Buffer.from(JSON.stringify(rawTransactions)), {
  level: 9,
});
writeFileSync(
  new URL("./raw-transactions.json.gz", import.meta.url),
  compressed,
);
writeFileSync(
  new URL("./transactions.json", import.meta.url),
  JSON.stringify(
    {
      version: 1,
      rawArchive: "raw-transactions.json.gz",
      rawArchiveSHA256: hex(sha(compressed)),
      chainCheckpoint: { header: hex(header), txid: root.id("hex"), height: 0 },
      lineageBoundary: "lineage-boundary.json.gz",
      lineageBoundarySHA256: hex(sha(boundaryBytes)),
      lineagePackage: "lineage-package.json.gz",
      lineagePackageSHA256: hex(sha(Buffer.from(canonical(packageBody)))),
      descriptor,
      state,
      keys: {
        seller: 41,
        recipients: identities.map((k) => Number(k.toString(10))),
        buyer: 44,
      },
      traces,
    },
    null,
    2,
  ) + "\n",
);
