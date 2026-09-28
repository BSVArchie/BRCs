// Exact byte encoder and unlocking ABI for the proposed revenue-listing-v1 family.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import {
  Transaction,
  TransactionSignature,
  Script,
  LockingScript,
  UnlockingScript,
  Spend,
  PrivateKey,
  P2PKH,
  Hash,
  BigNumber,
} from "../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js";
import {
  sha,
  hex,
  varint,
  digest,
  identity,
  u64,
  closed,
} from "../../../overlays/media/0192-0199/protocol.mjs";
export { Transaction, LockingScript, UnlockingScript, PrivateKey, P2PKH, Hash };
export const program = Buffer.from(
  readFileSync(new URL("./program.hex", import.meta.url), "utf8").trim(),
  "hex",
);
export const le = (n, size) => {
  const b = Buffer.alloc(size);
  let v = BigInt(n);
  assert(v >= 0n && v < 1n << BigInt(size * 8));
  for (let i = 0; i < size; i++) {
    b[i] = Number(v & 255n);
    v >>= 8n;
  }
  return b;
};
export const pub = (k) => k.toPublicKey().toString();
export const pkh = (k) =>
  Buffer.from(Hash.hash160(k.toPublicKey().encode(true)));
export const ys = (k) => Buffer.from(k.toPublicKey().getY().toArray("be", 32));
export function stateBytes(state) {
  closed(state, ["revision", "recipients"]);
  u64(state.revision);
  assert(state.recipients.length >= 1 && state.recipients.length <= 8);
  let last = "",
    total = 0;
  const entries = state.recipients.map((r) => {
    closed(r, ["identity", "weight"]);
    identity(r.identity);
    assert(r.identity > last);
    last = r.identity;
    assert(Number.isInteger(r.weight) && r.weight > 0 && r.weight <= 10000);
    total += r.weight;
    return Buffer.concat([Buffer.from(r.identity, "hex"), le(r.weight, 4)]);
  });
  assert(total <= 10000);
  return Buffer.concat([
    le(state.revision, 8),
    le(entries.length, 1),
    ...entries,
    Buffer.alloc((8 - entries.length) * 37),
  ]);
}
export function encode(descriptor, state) {
  identity(descriptor.seller);
  assert(["none", "seller-v1"].includes(descriptor.administration));
  for (const field of ["purchasePrice", "reserve"])
    assert(
      u64(descriptor[field]) > 0n &&
        u64(descriptor[field]) <= 2100000000000000n,
    );
  const listingId = digest("sale-listing", descriptor);
  const data = Buffer.concat([
    Buffer.from("ROSL"),
    Buffer.from([1]),
    Buffer.from(listingId, "hex"),
    Buffer.from(descriptor.termsDigest, "hex"),
    le(descriptor.purchasePrice, 8),
    le(descriptor.reserve, 8),
    Buffer.from(descriptor.seller, "hex"),
    Buffer.from([descriptor.administration === "seller-v1" ? 1 : 0]),
    stateBytes(state),
  ]);
  assert.equal(data.length, 424);
  return LockingScript.fromHex(
    hex(
      Buffer.concat([
        Buffer.from("4da801", "hex"),
        data,
        Buffer.from([0x75]),
        program,
      ]),
    ),
  );
}
// Inverse parsing also authenticates the registered program and descriptor. The
// data prefix alone is insufficient: a copied or altered program is another script.
export function decode(script, descriptor) {
  const raw = Buffer.from(script.toBinary());
  assert.equal(raw.length, 428 + program.length);
  assert(
    raw.subarray(0, 3).equals(Buffer.from("4da801", "hex")) &&
      raw[427] === 0x75,
  );
  assert(raw.subarray(428).equals(program), "family-program");
  const data = raw.subarray(3, 427),
    count = data[127];
  assert(count >= 1 && count <= 8);
  const state = {
    revision: data.readBigUInt64LE(119).toString(),
    recipients: [],
  };
  for (let i = 0; i < count; i++)
    state.recipients.push({
      identity: data.subarray(128 + i * 37, 161 + i * 37).toString("hex"),
      weight: data.readUInt32LE(161 + i * 37),
    });
  assert(
    raw.equals(Buffer.from(encode(descriptor, state).toBinary())),
    "descriptor-or-padding",
  );
  return state;
}
export const serializeOutput = (o) =>
  Buffer.concat([
    le(o.satoshis, 8),
    varint(o.lockingScript.toBinary().length),
    Buffer.from(o.lockingScript.toBinary()),
  ]);
export const output = (s, script) => ({
  satoshis: Number(s),
  lockingScript: script,
});
export function payoutOutputs(state, units) {
  return state.recipients.map((r) =>
    output(
      BigInt(units) * BigInt(r.weight),
      new P2PKH().lock(Hash.hash160([...Buffer.from(r.identity, "hex")])),
    ),
  );
}
export function adminReceipt(
  descriptor,
  operation,
  m,
  n,
  payout,
  commitment = Buffer.alloc(32),
) {
  return LockingScript.fromHex(
    hex(
      Buffer.concat([
        Buffer.from("006a4c56524f534c01", "hex"),
        le(operation, 1),
        Buffer.from(digest("sale-listing", descriptor), "hex"),
        le(m, 4),
        le(n, 4),
        le(payout, 8),
        commitment,
      ]),
    ),
  );
}
export function preimage(tx, index) {
  const input = tx.inputs[index],
    previous = input.sourceTransaction.outputs[input.sourceOutputIndex];
  return Buffer.from(
    TransactionSignature.format({
      sourceTXID: input.sourceTXID ?? input.sourceTransaction.id("hex"),
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: previous.satoshis,
      transactionVersion: tx.version,
      otherInputs: tx.inputs
        .filter((_, i) => i !== index)
        .map((x) => ({
          ...x,
          sourceTXID: x.sourceTXID ?? x.sourceTransaction.id("hex"),
        })),
      outputs: tx.outputs,
      inputIndex: index,
      subscript: Script.fromHex(previous.lockingScript.toHex()),
      inputSequence: input.sequence,
      lockTime: tx.lockTime,
      scope: 0x41,
    }),
  );
}
function sign(pre, key) {
  const s = key.sign([...sha(pre)]);
  return Buffer.concat([Buffer.from(s.toDER()), Buffer.from([0x41])]);
}
function push(bytes) {
  const n = bytes.length;
  if (n === 0) return Buffer.from([0]);
  if (n === 1 && bytes[0] >= 1 && bytes[0] <= 16)
    return Buffer.from([0x50 + bytes[0]]);
  if (n === 1 && bytes[0] === 129) return Buffer.from([0x4f]);
  return Buffer.concat([
    n <= 75
      ? Buffer.from([n])
      : n <= 255
        ? Buffer.from([76, n])
        : n <= 65535
          ? Buffer.concat([Buffer.from([77]), le(n, 2)])
          : Buffer.concat([Buffer.from([78]), le(n, 4)]),
    bytes,
  ]);
}
function scriptNumber(n) {
  n = BigInt(n);
  assert(n >= 0n);
  if (!n) return Buffer.alloc(0);
  let a = [];
  while (n) {
    a.push(Number(n & 255n));
    n >>= 8n;
  }
  if (a.at(-1) & 128) a.push(0);
  return Buffer.from(a);
}
export function unlock(tx, index, args) {
  const pre = preimage(tx, index);
  const prevouts = Buffer.concat(
    tx.inputs.map((i) =>
      Buffer.concat([
        Buffer.from(
          i.sourceTXID ?? i.sourceTransaction.id("hex"),
          "hex",
        ).reverse(),
        le(i.sourceOutputIndex, 4),
      ]),
    ),
  );
  let consentBytes = Buffer.alloc(0);
  if (args.operation === 6) {
    consentBytes = Buffer.alloc(584);
    args.consentKeys.forEach((key, i) => {
      const sig = sign(pre, key);
      consentBytes[i * 73] = sig.length;
      sig.copy(consentBytes, i * 73 + 1);
    });
  }
  const fields = [
    pre,
    prevouts,
    scriptNumber(args.operation),
    Buffer.from(args.receipt.toBinary()),
    args.recipientY ?? Buffer.alloc(0),
    scriptNumber(args.splitAmount ?? 0),
    scriptNumber(args.payoutUnits ?? 0),
    args.otherPrevious ?? Buffer.alloc(0),
    args.newState ? stateBytes(args.newState) : Buffer.alloc(0),
    args.newKeyYs ?? Buffer.alloc(0),
    args.adminKey ? sign(pre, args.adminKey) : Buffer.alloc(0),
    consentBytes,
    args.changeHash ?? Buffer.alloc(20),
    scriptNumber(args.changeAmount ?? 0),
  ];
  return UnlockingScript.fromHex(hex(Buffer.concat(fields.map(push))));
}
export function evaluate(tx, index) {
  const inp = tx.inputs[index],
    src = inp.sourceTransaction.outputs[inp.sourceOutputIndex];
  const spend = new Spend({
    sourceTXID: inp.sourceTXID ?? inp.sourceTransaction.id("hex"),
    sourceOutputIndex: inp.sourceOutputIndex,
    sourceSatoshis: src.satoshis,
    lockingScript: LockingScript.fromHex(src.lockingScript.toHex()),
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_, i) => i !== index)
      .map((x) => ({
        ...x,
        sourceTXID: x.sourceTXID ?? x.sourceTransaction.id("hex"),
      })),
    outputs: tx.outputs,
    inputIndex: index,
    unlockingScript: UnlockingScript.fromHex(inp.unlockingScript.toHex()),
    inputSequence: inp.sequence,
    lockTime: tx.lockTime,
    memoryLimit: 128 * 1024 * 1024,
  });
  return spend.validate();
}
