import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
if (!process.env.RUNAR_ROOT)
  throw Error("Set RUNAR_ROOT to the pinned compiler checkout");
const commit = "b3f08f2cc2349c311904d2c745dc19d65f23e8ca";
if (
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: process.env.RUNAR_ROOT,
    encoding: "utf8",
  }).trim() !== commit
)
  throw Error("Compiler checkout is not pinned commit");
execFileSync(
  "git",
  [
    "diff",
    "--exit-code",
    "HEAD",
    "--",
    "packages/runar-compiler",
    "packages/runar-ir-schema",
    "package-lock.json",
  ],
  { cwd: process.env.RUNAR_ROOT, stdio: "pipe" },
);
const { compile } = await import(
  pathToFileURL(
    process.env.RUNAR_ROOT + "/packages/runar-compiler/src/index.ts",
  )
);
const source = readFileSync(
  new URL("./RevenueListing.runar.ts", import.meta.url),
  "utf8",
);
const result = compile(source, { fileName: "RevenueListing.runar.ts" });
if (!result.success) {
  console.error(result.diagnostics);
  process.exit(1);
}
const raw = Buffer.from(result.scriptHex, "hex");
if (
  result.artifact.codeSeparatorIndices?.length !== 1 ||
  result.artifact.codeSeparatorIndex !== 2 ||
  raw[2] !== 0xab
)
  throw Error("Unexpected compiler separator layout");
// Authenticate the data prefix as part of full scriptCode. Remove only this known
// opcode; never byte-replace 0xab inside pushed constants.
const normalized = [],
  replacements = [];
for (let at = 0; at < raw.length; ) {
  const start = at,
    opcode = raw[at++];
  let size = 0;
  if (opcode >= 1 && opcode <= 75) size = opcode;
  else if (opcode === 76) size = raw[at++];
  else if (opcode === 77) {
    size = raw.readUInt16LE(at);
    at += 2;
  } else if (opcode === 78) {
    size = raw.readUInt32LE(at);
    at += 4;
  }
  if (at + size > raw.length) throw Error("Truncated compiler push");
  at += size;
  if (start === 2) continue;
  if (opcode === 0x8d) {
    // Use the common Genesis/Chronicle subset. For this bounded integer the
    // restored OP_2MUL is exactly OP_2 OP_MUL; pushed bytes are never rewritten.
    normalized.push(Buffer.from([0x52, 0x95]));
    replacements.push({ byte: start, from: "OP_2MUL", to: ["OP_2", "OP_MUL"] });
  } else normalized.push(raw.subarray(start, at));
}
if (replacements.length !== 1)
  throw Error("Unexpected compiler multiplication layout");
const program = Buffer.concat(normalized);
const hash = (b) => createHash("sha256").update(b).digest("hex");
const artifact = {
  version: 1,
  compilerCommit: "b3f08f2cc2349c311904d2c745dc19d65f23e8ca",
  compilerOptions: { fileName: "RevenueListing.runar.ts" },
  sourceSHA256: hash(source),
  compilerProgramSHA256: hash(raw),
  programSHA256: hash(program),
  normalization: {
    removeOpcodeAtByte: 2,
    opcode: "OP_CODESEPARATOR",
    replacements,
  },
  abi: result.artifact.abi,
};
if (process.argv.includes("--check")) {
  const existing = JSON.parse(
    readFileSync(new URL("./artifact.json", import.meta.url), "utf8"),
  );
  if (
    JSON.stringify(existing) !== JSON.stringify(artifact) ||
    readFileSync(new URL("./program.hex", import.meta.url), "utf8").trim() !==
      program.toString("hex")
  )
    throw Error("Frozen family build differs");
} else {
  writeFileSync(
    new URL("./artifact.json", import.meta.url),
    JSON.stringify(artifact, null, 2) + "\n",
  );
  writeFileSync(
    new URL("./program.hex", import.meta.url),
    program.toString("hex") + "\n",
  );
}
console.log(
  JSON.stringify({
    bytes: program.length,
    sha256: hash(program),
    warnings: result.diagnostics,
  }),
);
