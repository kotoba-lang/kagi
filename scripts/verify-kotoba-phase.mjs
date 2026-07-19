import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [webPath, wasmPath, hostPath] = process.argv.slice(2);
if (!webPath || !wasmPath || !hostPath) throw new Error("missing conformance paths");
const phases = [-1n, 0n, 1n, 2n, 3n, 4n];
const operations = [":item/create", ":item/update", ":item/rotate", ":share/grant",
  ":share/revoke", ":item/reveal", ":item/list", ":unknown/op"];
const dispositions = [":hold", ":commit", ":escalate", ":unknown/disposition"];
const writes = new Set(operations.slice(0, 5));
const reads = new Set([":item/reveal", ":item/list"]);
function expected(phase, op, disposition) {
  const level = phase >= 0n && phase <= 3n ? phase : 1n;
  const auto = level === 3n || op === ":item/create" || op === ":item/update" ||
    (level === 2n && op === ":share/grant");
  if (disposition === ":hold") return [":hold", ":none"];
  if (reads.has(op)) return [disposition, ":none"];
  if (level === 0n || !writes.has(op)) return [":hold", ":phase-disabled"];
  if (disposition === ":commit" && !auto) return [":escalate", ":phase-approval"];
  return [disposition, ":none"];
}

const web = await import(pathToFileURL(path.resolve(webPath)));
if (web.kotobaArtifact.requiredCapabilities.length !== 0)
  throw new Error("Kagi phase Web graph requested a capability");
if (web.instantiateKotoba().main() !== 42n) throw new Error("Kagi phase Web main mismatch");
const host = await import(pathToFileURL(path.resolve(hostPath)));
const wasmBytes = fs.readFileSync(path.resolve(wasmPath));
let checked = 0;
for (const phase of phases) for (const op of operations) for (const disposition of dispositions) {
  const [expectedDisposition, expectedReason] = expected(phase, op, disposition);
  if (web.instantiateKotoba()["gate-check"](
      phase, op, disposition, expectedDisposition, expectedReason) !== 42n)
    throw new Error(`Web phase mismatch: ${phase}/${op}/${disposition}`);
  const wasm = await host.instantiateKotoba(wasmBytes);
  if (wasm.instance.exports["gate-check"](
      phase, op, disposition, expectedDisposition, expectedReason) !== 42n)
    throw new Error(`Wasm phase mismatch: ${phase}/${op}/${disposition}`);
  checked++;
}
console.log(`kagi-phase: ${checked} Web/Wasm matrix cases passed`);
