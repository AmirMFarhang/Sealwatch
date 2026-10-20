// Minimal canonical stored ZIP: no extraction, compression, symlinks or path traversal.
import { assert } from "../core/validation.js";
const LIMIT = 16 * 1024 * 1024;
function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) { c ^= b; for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}
export function encodeZip(files: ReadonlyMap<string, Buffer>): Buffer {
  assert(files.size > 0 && files.size <= 8, "audit pack file count invalid");
  const locals: Buffer[] = [], central: Buffer[] = []; let offset = 0, total = 0;
  for (const [name, bytes] of [...files].sort(([a], [b]) => a.localeCompare(b, "en"))) {
    assert(/^[a-z][a-z0-9-]*\.json$/.test(name), "audit pack filename invalid");
    total += bytes.length; assert(bytes.length <= 4 * 1024 * 1024 && total <= LIMIT, "audit pack too large");
    const n = Buffer.from(name), crc = crc32(bytes), local = Buffer.alloc(30), cd = Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x800, 6); local.writeUInt16LE(33, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(bytes.length, 18); local.writeUInt32LE(bytes.length, 22); local.writeUInt16LE(n.length, 26);
    cd.writeUInt32LE(0x02014b50); cd.writeUInt16LE(0x314, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(0x800, 8); cd.writeUInt16LE(33, 14);
    cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(bytes.length, 20); cd.writeUInt32LE(bytes.length, 24); cd.writeUInt16LE(n.length, 28); cd.writeUInt32LE(0x81800000, 38); cd.writeUInt32LE(offset, 42);
    locals.push(local, n, bytes); central.push(cd, n); offset += local.length + n.length + bytes.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(files.size, 8); end.writeUInt16LE(files.size, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
export function decodeZip(bytes: Buffer): Map<string, Buffer> {
  assert(bytes.length <= LIMIT + 8192 && bytes.length >= 22, "audit ZIP size invalid");
  const files = new Map<string, Buffer>(); let at = 0;
  while (at + 30 <= bytes.length && bytes.readUInt32LE(at) === 0x04034b50) {
    const n = bytes.readUInt16LE(at + 26), extra = bytes.readUInt16LE(at + 28), size = bytes.readUInt32LE(at + 18);
    assert(!extra && bytes.readUInt16LE(at + 8) === 0 && size <= 4 * 1024 * 1024, "only canonical stored ZIP files accepted");
    const end = at + 30 + n + size; assert(end <= bytes.length, "audit ZIP truncated");
    const name = bytes.subarray(at + 30, at + 30 + n).toString("utf8");
    assert(!files.has(name) && files.size < 8, "duplicate/excess audit ZIP files");
    files.set(name, bytes.subarray(at + 30 + n, end)); at = end;
  }
  assert(encodeZip(files).equals(bytes), "audit ZIP checksum/directory/noncanonical content invalid");
  return files;
}
