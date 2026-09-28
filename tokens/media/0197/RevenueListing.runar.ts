import {
  SmartContract,
  assert,
  checkSig,
  checkPreimage,
  hash256,
  sha256,
  hash160,
  cat,
  substr,
  len,
  num2bin,
  bin2num,
  ecMakePoint,
  ecOnCurve,
  extractHashPrevouts,
  extractHashSequence,
  extractOutpoint,
  extractOutputHash,
} from "runar-lang";
import type { ByteString, Sig, PubKey, SigHashPreimage } from "runar-lang";

// Fixed binary data prefix followed by this parameter-free program. No CODESEPARATOR.
// All metadata is read from the authenticated full scriptCode, never from caller flags.
class RevenueListing extends SmartContract {
  constructor() {
    super();
  }

  private compact(cp_data: ByteString, cp_offset: bigint): bigint {
    const cp_tag = bin2num(cat(substr(cp_data, cp_offset, 1n), "00"));
    let cp_value = cp_tag;
    if (cp_tag === 253n) {
      cp_value = bin2num(cat(substr(cp_data, cp_offset + 1n, 2n), "00"));
      assert(cp_value >= 253n);
    } else if (cp_tag === 254n) {
      cp_value = bin2num(cat(substr(cp_data, cp_offset + 1n, 4n), "00"));
      assert(cp_value >= 65536n);
    } else {
      assert(cp_tag < 253n);
    }
    assert(cp_value <= 1048576n);
    return cp_value + 0n;
  }
  private width(vw_data: ByteString, vw_offset: bigint): bigint {
    const vw_tag = bin2num(cat(substr(vw_data, vw_offset, 1n), "00"));
    let vw_size = 1n;
    if (vw_tag === 253n) {
      vw_size = 3n;
    }
    if (vw_tag === 254n) {
      vw_size = 5n;
    }
    return vw_size + 0n;
  }
  private lengthPrefix(lp_n: bigint): ByteString {
    assert(lp_n >= 0n && lp_n <= 1048576n);
    let lp_result: ByteString = "";
    if (lp_n < 253n) {
      lp_result = substr(num2bin(lp_n, 2n), 0n, 1n);
    }
    if (lp_n >= 253n && lp_n <= 65535n) {
      lp_result = cat("fd", substr(num2bin(lp_n, 3n), 0n, 2n));
    }
    if (lp_n >= 65536n) {
      lp_result = cat("fe", num2bin(lp_n, 4n));
    }
    return cat(lp_result, "");
  }
  private output(out_amount: bigint, out_script: ByteString): ByteString {
    assert(out_amount >= 1n && out_amount <= 2100000000000000n);
    return cat(
      cat(num2bin(out_amount, 8n), this.lengthPrefix(len(out_script))),
      out_script,
    );
  }
  private reverse32(rv_data: ByteString): ByteString {
    assert(len(rv_data) === 32n);
    let rv_reversed: ByteString = "";
    for (let rv_i = 0n; rv_i < 32n; rv_i++) {
      rv_reversed = cat(substr(rv_data, rv_i, 1n), rv_reversed);
    }
    return cat(rv_reversed, "");
  }
  private point(pt_key: ByteString, pt_y: ByteString): boolean {
    assert(len(pt_key) === 33n && len(pt_y) === 32n);
    const pt_prefix = bin2num(cat(substr(pt_key, 0n, 1n), "00"));
    const pt_x = bin2num(cat(this.reverse32(substr(pt_key, 1n, 32n)), "00"));
    const pt_yn = bin2num(cat(this.reverse32(pt_y), "00"));
    assert(
      (pt_prefix === 2n || pt_prefix === 3n) && pt_prefix === 2n + (pt_yn % 2n),
    );
    return ecOnCurve(ecMakePoint(pt_x, pt_yn));
  }
  private predecessor(
    pr_raw: ByteString,
    pr_outpoint: ByteString,
    pr_script: ByteString,
  ): bigint {
    assert(
      len(pr_raw) <= 1048576n &&
        hash256(pr_raw) === substr(pr_outpoint, 0n, 32n),
    );
    const pr_wanted = bin2num(cat(substr(pr_outpoint, 32n, 4n), "00"));
    const pr_version = bin2num(cat(substr(pr_raw, 0n, 4n), "00"));
    assert(pr_version === 1n || pr_version === 2n);
    const pr_inputs = this.compact(pr_raw, 4n);
    assert(pr_inputs >= 1n && pr_inputs <= 8n);
    let pr_cursor = 4n + this.width(pr_raw, 4n);
    for (let pr_i = 0n; pr_i < 8n; pr_i++) {
      if (pr_i < pr_inputs) {
        pr_cursor = pr_cursor + 36n;
        const pr_size = this.compact(pr_raw, pr_cursor);
        pr_cursor = pr_cursor + this.width(pr_raw, pr_cursor) + pr_size + 4n;
        assert(pr_cursor <= len(pr_raw));
      }
    }
    const pr_outputs = this.compact(pr_raw, pr_cursor);
    assert(pr_outputs >= 1n && pr_outputs <= 11n && pr_wanted < pr_outputs);
    pr_cursor = pr_cursor + this.width(pr_raw, pr_cursor);
    let pr_value = 0n;
    for (let pr_i = 0n; pr_i < 11n; pr_i++) {
      if (pr_i < pr_outputs) {
        const pr_amount = bin2num(cat(substr(pr_raw, pr_cursor, 8n), "00"));
        assert(pr_amount <= 2100000000000000n);
        pr_cursor = pr_cursor + 8n;
        const pr_size = this.compact(pr_raw, pr_cursor);
        pr_cursor = pr_cursor + this.width(pr_raw, pr_cursor);
        const pr_outputScript = substr(pr_raw, pr_cursor, pr_size);
        if (pr_i === pr_wanted) {
          assert(pr_outputScript === pr_script);
          pr_value = pr_amount;
        }
        pr_cursor = pr_cursor + pr_size;
      }
    }
    assert(pr_cursor + 4n === len(pr_raw));
    return pr_value + 0n;
  }

  public spend(
    preimage: SigHashPreimage,
    prevouts: ByteString,
    operation: bigint,
    receipt: ByteString,
    recipientY: ByteString,
    splitAmount: bigint,
    payoutUnits: bigint,
    otherPrevious: ByteString,
    newState: ByteString,
    newKeyYs: ByteString,
    adminSignature: Sig,
    consents: ByteString,
    changeHash: ByteString,
    changeAmount: bigint,
  ) {
    assert(checkPreimage(preimage));
    assert(len(preimage) <= 1048576n);
    const scriptLength = this.compact(preimage, 104n);
    const scriptStart = 104n + this.width(preimage, 104n);
    const script = substr(preimage, scriptStart, scriptLength);
    assert(scriptStart + scriptLength + 52n === len(preimage));
    assert(
      substr(script, 0n, 3n) === "4da801" && substr(script, 427n, 1n) === "75",
    );
    const data = substr(script, 3n, 424n);
    assert(substr(data, 0n, 5n) === "524f534c01");
    const listingId = substr(data, 5n, 32n);
    const terms = substr(data, 37n, 32n);
    const price = bin2num(cat(substr(data, 69n, 8n), "00"));
    const reserve = bin2num(cat(substr(data, 77n, 8n), "00"));
    const seller = substr(data, 85n, 33n) as PubKey;
    const administration = bin2num(cat(substr(data, 118n, 1n), "00"));
    const revision = bin2num(cat(substr(data, 119n, 8n), "00"));
    const count = bin2num(cat(substr(data, 127n, 1n), "00"));
    assert(price >= 1n && price <= 2100000000000000n);
    assert(reserve >= 1n && reserve <= 2100000000000000n);
    assert(administration <= 1n && count >= 1n && count <= 8n);
    const version = bin2num(cat(substr(preimage, 0n, 4n), "00"));
    assert(version === 1n || version === 2n);
    const tail = scriptStart + scriptLength;
    const amount = bin2num(cat(substr(preimage, tail, 8n), "00"));
    assert(amount >= reserve && amount <= 2100000000000000n);
    assert(substr(preimage, tail + 8n, 4n) === "ffffffff");
    assert(substr(preimage, tail + 44n, 8n) === "0000000041000000");
    assert(len(prevouts) % 36n === 0n);
    const inputCount = len(prevouts) / 36n;
    assert(inputCount >= 2n && inputCount <= 8n);
    assert(hash256(prevouts) === extractHashPrevouts(preimage));
    let sequences: ByteString = "";
    for (let i = 0n; i < 8n; i++) {
      if (i < inputCount) {
        sequences = cat(sequences, "ffffffff");
      }
    }
    assert(hash256(sequences) === extractHashSequence(preimage));
    const self = extractOutpoint(preimage);
    let inputIndex = 0n;
    if (operation === 3n && self === substr(prevouts, 36n, 36n)) {
      inputIndex = 1n;
    }
    assert(self === substr(prevouts, inputIndex * 36n, 36n));
    assert(operation >= 1n && operation <= 6n);

    let totalWeight = 0n;
    for (let i = 0n; i < 8n; i++) {
      const slot = substr(data, 128n + i * 37n, 37n);
      if (i < count) {
        const weight = bin2num(cat(substr(slot, 33n, 4n), "00"));
        assert(weight >= 1n && weight <= 10000n);
        totalWeight = totalWeight + weight;
      } else {
        assert(
          slot ===
            "00000000000000000000000000000000000000000000000000000000000000000000000000",
        );
      }
    }
    assert(totalWeight <= 10000n);
    let outputs: ByteString = "";
    let payout = 0n;
    let payoutOutputs: ByteString = "";
    if (operation === 1n) {
      assert(
        len(receipt) === 171n &&
          substr(receipt, 0n, 10n) === "006a4ca7524f534c0101",
      );
      assert(
        substr(receipt, 10n, 32n) === listingId &&
          substr(receipt, 139n, 32n) === terms,
      );
      assert(this.point(substr(receipt, 106n, 33n), recipientY));
      assert(splitAmount === 0n && payoutUnits === 0n);
      outputs = this.output(amount + price, script);
    } else {
      assert(administration === 1n);
      assert(
        len(adminSignature) >= 9n &&
          substr(adminSignature, len(adminSignature) - 1n, 1n) === "41",
      );
      assert(checkSig(adminSignature, seller));
      if (operation === 2n) {
        assert(
          splitAmount >= reserve &&
            amount - splitAmount >= reserve &&
            payoutUnits === 0n,
        );
        outputs = cat(
          this.output(splitAmount, script),
          this.output(amount - splitAmount, script),
        );
      } else if (operation === 3n) {
        assert(inputCount >= 3n && splitAmount === 0n && payoutUnits === 0n);
        const other = substr(prevouts, (1n - inputIndex) * 36n, 36n);
        assert(other !== self);
        const otherValue = this.predecessor(otherPrevious, other, script);
        assert(otherValue >= reserve);
        outputs = this.output(amount + otherValue, script);
      } else if (operation === 4n || operation === 5n) {
        assert(splitAmount === 0n);
        let units = payoutUnits;
        if (operation === 4n) {
          assert(units >= 1n);
          payout = units * totalWeight;
          assert(amount - payout >= reserve);
          outputs = this.output(amount - payout, script);
        } else {
          assert(payoutUnits === 0n);
          units = (amount + totalWeight - 1n) / totalWeight;
          payout = units * totalWeight;
        }
        assert(payout <= 2100000000000000n);
        for (let i = 0n; i < 8n; i++) {
          if (i < count) {
            const key = substr(data, 128n + i * 37n, 33n);
            const weight = bin2num(cat(substr(data, 161n + i * 37n, 4n), "00"));
            const destination = cat(cat("76a914", hash160(key)), "88ac");
            payoutOutputs = cat(
              payoutOutputs,
              this.output(units * weight, destination),
            );
          }
        }
      } else {
        assert(operation === 6n && splitAmount === 0n && payoutUnits === 0n);
        assert(
          len(newState) === 305n &&
            len(newKeyYs) === 256n &&
            len(consents) === 584n,
        );
        assert(revision < 18446744073709551615n);
        assert(bin2num(cat(substr(newState, 0n, 8n), "00")) === revision + 1n);
        const newCount = bin2num(cat(substr(newState, 8n, 1n), "00"));
        assert(newCount >= 1n && newCount <= 8n);
        let newWeight = 0n;
        let previousKey = 0n;
        for (let i = 0n; i < 8n; i++) {
          if (i < count) {
            const key = substr(data, 128n + i * 37n, 33n) as PubKey;
            const size = bin2num(cat(substr(consents, i * 73n, 1n), "00"));
            assert(size >= 9n && size <= 72n);
            const signature = substr(consents, i * 73n + 1n, size) as Sig;
            assert(substr(signature, size - 1n, 1n) === "41");
            assert(
              substr(consents, i * 73n + 1n + size, 72n - size) ===
                substr(
                  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                  0n,
                  72n - size,
                ),
            );
            assert(checkSig(signature, key));
          } else {
            assert(
              substr(consents, i * 73n, 73n) ===
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            );
          }
          const slot = substr(newState, 9n + i * 37n, 37n);
          if (i < newCount) {
            const key = substr(slot, 0n, 33n);
            const keyNumber =
              bin2num(cat(this.reverse32(substr(key, 1n, 32n)), "00")) +
              bin2num(cat(substr(key, 0n, 1n), "00")) *
                0x10000000000000000000000000000000000000000000000000000000000000000n;
            assert(keyNumber > previousKey);
            previousKey = keyNumber;
            assert(this.point(key, substr(newKeyYs, i * 32n, 32n)));
            const weight = bin2num(cat(substr(slot, 33n, 4n), "00"));
            assert(weight >= 1n && weight <= 10000n);
            newWeight = newWeight + weight;
          } else {
            assert(
              slot ===
                "00000000000000000000000000000000000000000000000000000000000000000000000000",
            );
            assert(
              substr(newKeyYs, i * 32n, 32n) ===
                "0000000000000000000000000000000000000000000000000000000000000000",
            );
          }
        }
        assert(newWeight <= 10000n);
        const newData = cat(substr(data, 0n, 119n), newState);
        const newScript = cat(
          cat(cat("4da801", newData), "75"),
          substr(script, 428n, len(script) - 428n),
        );
        outputs = this.output(amount, newScript);
      }
      const receiptPayout =
        operation === 4n
          ? payoutUnits * totalWeight
          : operation === 5n
            ? ((amount + totalWeight - 1n) / totalWeight) * totalWeight
            : 0n;
      const receiptCommitment =
        operation === 4n || operation === 5n
          ? sha256(payoutOutputs)
          : operation === 6n
            ? sha256(newState)
            : "0000000000000000000000000000000000000000000000000000000000000000";
      const adminData = cat(
        cat(
          cat(
            cat(cat("524f534c01", num2bin(operation, 1n)), listingId),
            num2bin(operation === 3n ? 2n : 1n, 4n),
          ),
          num2bin(operation === 2n ? 2n : operation === 5n ? 0n : 1n, 4n),
        ),
        cat(num2bin(receiptPayout, 8n), receiptCommitment),
      );
      assert(receipt === cat("006a4c56", adminData));
    }
    if (operation !== 3n) {
      assert(len(otherPrevious) === 0n);
    }
    if (operation !== 6n) {
      assert(len(newState) === 0n && len(newKeyYs) === 0n);
      assert(len(consents) === 0n);
    }
    if (operation !== 1n) {
      assert(len(recipientY) === 0n);
    }
    if (operation === 1n) {
      assert(len(adminSignature) === 0n);
    }
    outputs = cat(cat(outputs, this.output(1n, receipt)), payoutOutputs);
    assert(changeAmount >= 0n && len(changeHash) === 20n);
    if (changeAmount === 0n) {
      assert(changeHash === "0000000000000000000000000000000000000000");
    }
    if (changeAmount > 0n) {
      outputs = cat(
        outputs,
        this.output(changeAmount, cat(cat("76a914", changeHash), "88ac")),
      );
    }
    assert(hash256(outputs) === extractOutputHash(preimage));
  }
}
