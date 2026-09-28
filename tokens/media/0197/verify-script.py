"""Independent BitcoinX Script execution of the frozen family transactions.

Public fixture keys/UTXOs only; no wallet or network calls. This establishes
Script acceptance/rejection, not chain inclusion or deployed economic safety.
"""

import json, gzip, hashlib
from pathlib import Path
from bitcoinx import Tx, TxInputContext, InterpreterLimits, MinerPolicy, PublicKey

corpus = json.loads(Path(__file__).with_name("transactions.json").read_text())
archive = Path(__file__).with_name(corpus["rawArchive"]).read_bytes()
assert hashlib.sha256(archive).hexdigest() == corpus["rawArchiveSHA256"]
raw = json.loads(gzip.decompress(archive))
limits = InterpreterLimits(
    MinerPolicy(1048576, 128, 128 * 1024 * 1024, 1000000, 8),
    is_genesis_enabled=True,
    is_consensus=False,
)
passed = 0
for case in corpus["traces"]:
    tx = Tx.from_hex(raw[case["txid"]])
    outcomes = []
    for i, entry in enumerate(case["sources"]):
        source = Tx.from_hex(raw[entry["txid"]])
        assert tx.inputs[i].prev_hash == source.hash()
        assert tx.inputs[i].prev_idx == entry["index"]
        context = TxInputContext(tx, i, source.outputs[entry["index"]])
        try:
            valid = context.verify_input(limits, is_utxo_after_genesis=True)
        except Exception as e:
            valid = False
            reason = type(e).__name__
            if case["expected"] == "accept":
                print(case["name"], i, reason, str(e)[:500])
        outcomes.append(valid)
    assert all(outcomes) == (case["expected"] == "accept"), (case["name"], outcomes)
    passed += 1
print(
    json.dumps(
        {
            "independentScriptCases": passed,
            "interpreter": "bitcoinX 0.9",
            "realECDSA": True,
        }
    )
)

# Independently parse every partial BEEF and resolve the shared ancestor DAG.
import importlib.util, base64, hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

here = Path(__file__).parent
oracle_path = here / "../../../overlays/media/0192-0199/beef-oracle.py"
spec = importlib.util.spec_from_file_location("beef_oracle", oracle_path.resolve())
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
payload = gzip.decompress((here / corpus["lineagePackage"]).read_bytes())
assert hashlib.sha256(payload).hexdigest() == corpus["lineagePackageSHA256"]
pkg = json.loads(payload)
root = (0, corpus["chainCheckpoint"]["txid"])
txs = {}
listing_ids = set()
for item in pkg["transactions"]:
    group, _ = oracle.parse_beef(base64.b64decode(item["beef"]), item["txid"], {root})
    listing_ids.add(item["txid"])
    for ident, tx in group.items():
        if ident in txs:
            assert tx.to_bytes() == txs[ident].to_bytes()
        txs[ident] = tx
for ident, tx in txs.items():
    if ident == root[1]:
        continue
    for i, inp in enumerate(tx.inputs):
        parent = txs[inp.prev_hash[::-1].hex()]
        assert TxInputContext(tx, i, parent.outputs[inp.prev_idx]).verify_input(
            limits, is_utxo_after_genesis=True
        )
auth = pkg["genesis"]
sig = base64.b64decode(auth["signature"])
seller = bytes.fromhex(pkg["descriptor"]["seller"])
assert sig[:4] == bytes.fromhex("42423301") and sig[4:37] == seller and sig[37] == 0
pre = (
    b"BRC-OUTPUT/1/sale-genesis\0"
    + json.dumps(auth["body"], sort_keys=True, separators=(",", ":")).encode()
)
offset = int.from_bytes(
    hmac.new(
        seller, b"2-message signing-" + base64.b64encode(sig[38:70]), hashlib.sha256
    ).digest(),
    "big",
)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
derived = (
    PublicKey.from_bytes(seller)
    .add(offset.to_bytes(32, "big"))
    .to_bytes(compressed=True)
)
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), derived).verify(
    sig[70:], pre, ec.ECDSA(hashes.SHA256())
)
seen = set()


def walk(txid, index):
    if (txid, index) in seen:
        return
    assert txid in listing_ids, "missing ancestor"
    tx = txs[txid]
    assert (
        tx.outputs[index]
        .script_pubkey.to_bytes()
        .startswith(bytes.fromhex("4da801524f534c01"))
    )
    if txid == auth["body"]["genesis"]["txid"]:
        assert (
            index == 0
            and tx.inputs[0].prev_hash[::-1].hex()
            == pkg["descriptor"]["lineageAnchor"]["txid"]
            and tx.inputs[0].prev_idx
            == pkg["descriptor"]["lineageAnchor"]["outputIndex"]
        )
    else:
        receipts = [
            o.script_pubkey.to_bytes()
            for o in tx.outputs
            if o.script_pubkey.to_bytes().startswith(bytes.fromhex("006a4c"))
            and o.script_pubkey.to_bytes()[4:8] == b"ROSL"
        ]
        assert len(receipts) == 1
        count = 2 if receipts[0][9] == 3 else 1
        for inp in tx.inputs[:count]:
            walk(inp.prev_hash[::-1].hex(), inp.prev_idx)
    seen.add((txid, index))


walk(pkg["target"]["txid"], pkg["target"]["outputIndex"])
assert len(seen) == 9
print(
    json.dumps(
        {
            "independentLineageTransactions": len(listing_ids),
            "sharedDAGOutpoints": len(seen),
            "authorizedGenesis": True,
            "boundedPackageBytes": len(payload),
        }
    )
)

# Same frozen boundary case as the JS oracle: real added value, false ancestry.
boundary_bytes = gzip.decompress((here / corpus["lineageBoundary"]).read_bytes())
assert hashlib.sha256(boundary_bytes).hexdigest() == corpus["lineageBoundarySHA256"]
boundary = json.loads(boundary_bytes)
for item in (boundary["copy"], boundary["merge"]):
    group, _ = oracle.parse_beef(base64.b64decode(item["beef"]), item["txid"], {root})
    for ident, tx in group.items():
        if ident in txs:
            assert tx.to_bytes() == txs[ident].to_bytes()
        txs[ident] = tx
    listing_ids.add(item["txid"])
merged = txs[boundary["merge"]["txid"]]
previous = [txs[i.prev_hash[::-1].hex()].outputs[i.prev_idx] for i in merged.inputs]
assert (
    previous[0].script_pubkey
    == previous[1].script_pubkey
    == merged.outputs[0].script_pubkey
)
assert merged.outputs[0].value == previous[0].value + previous[1].value
assert merged.outputs[1].script_pubkey.to_bytes()[9] == 3
for i, prev in enumerate(previous):
    assert TxInputContext(merged, i, prev).verify_input(
        limits, is_utxo_after_genesis=True
    )
seen.clear()
try:
    walk(boundary["merge"]["txid"], 0)
except AssertionError:
    pass
else:
    raise AssertionError("unrelated funded copy accepted as authorized lineage")
print(
    json.dumps(
        {
            "independentFundedCopyMerge": "Script accepts conserved value; lineage rejects unrelated history"
        }
    )
)
