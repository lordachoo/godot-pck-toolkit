"""
recover_godot_key.py — recover the 32-byte AES-256 script-encryption key baked
into a Godot export by brute-forcing 32-byte windows of the executable against
the encrypted PCK directory. A candidate is accepted only if AES-256-CFB128
decryption reproduces the directory's stored MD5 (definitive check).

Strategy (fast + visible):
  * Cheap per-candidate filter: decrypt only the first CFB block and check the
    first entry's path_len is sane (1..4096). CFB block0: P0 = C0 ^ E(key,IV).
  * Search the initialized-data sections first (.rdata/.data) where compiled
    keys live, then .rsrc, then .text, then anything left.
  * Live progress, line-buffered (run with `python -u`).

Usage:  python -u recover_godot_key.py <exe> [--out recovered/key.bin]
"""
import sys
import time
import struct
import argparse
from Crypto.Cipher import AES

import godot_pck_common as g


def pe_sections(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        return []
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    st = pe + 24 + optsz
    out = []
    for i in range(nsec):
        s = data[st + i * 40: st + i * 40 + 40]
        name = s[0:8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, rp = struct.unpack_from("<IIII", s, 8)
        if rs:
            out.append((name, rp, rs))
    return out


def search_ranges(data: bytes, pck_start: int):
    """Yield (label, start, end) to scan, most-likely-first, de-overlapped."""
    secs = {n: (rp, rs) for n, rp, rs in pe_sections(data)}
    order = [".rdata", ".data", ".rsrc", ".pdata", ".text", ".reloc"]
    seen = []
    for name in order:
        if name in secs:
            rp, rs = secs[name]
            end = min(rp + rs, pck_start)
            if end > rp:
                seen.append((name, rp, end))
    covered_end = max([e for _, _, e in seen], default=0)
    if covered_end < pck_start:
        seen.append(("<rest>", covered_end, pck_start))
    return seen


def recover(data: bytes):
    pck_start = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck_start)
    if not hdr["dir_encrypted"]:
        raise SystemExit("Directory is NOT encrypted — no key needed.")
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])
    iv = fae["iv"]
    c0_4 = int.from_bytes(fae["ciphertext"][:4], "little")

    print(f"PCK @ {pck_start}  godot {hdr['godot']}  v{hdr['version']}", flush=True)
    print(f"file_count={fae['file_count']}  dir blob={fae['length']}B  "
          f"md5={fae['md5'].hex()}", flush=True)

    new = AES.new
    ECB = AES.MODE_ECB
    frombytes = int.from_bytes

    def scan(label, start, end):
        t0 = time.time()
        n = 0
        for off in range(start, end - 32 + 1):
            key = data[off:off + 32]
            ks = new(key, ECB).encrypt(iv)
            sl = c0_4 ^ frombytes(ks[:4], "little")
            n += 1
            if 1 <= sl <= 4096:
                if g.verify_key(key, fae) is not None:
                    print(f"  [{label}] HIT at offset {off} after {n:,} keys", flush=True)
                    return key, off
            if n % 1_000_000 == 0:
                rate = n / (time.time() - t0 + 1e-9)
                print(f"  [{label}] {n:,}/{end-start-31:,}  ({rate:,.0f}/s)", flush=True)
        print(f"  [{label}] done ({n:,} keys, {time.time()-t0:.0f}s) — no hit", flush=True)
        return None, None

    for label, start, end in search_ranges(data, pck_start):
        print(f"Scanning {label}: [{start}, {end})  = {end-start:,} bytes", flush=True)
        key, off = scan(label, start, end)
        if key:
            return key, off, hdr, fae
    raise SystemExit("Key NOT found anywhere in the PE region.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--out", default="../recovered/key.bin")
    args = ap.parse_args()
    data = open(args.exe, "rb").read()
    t = time.time()
    key, off, hdr, fae = recover(data)
    print(f"\nRECOVERED KEY (hex): {key.hex()}", flush=True)
    print(f"  offset: {off}   elapsed: {time.time()-t:.1f}s", flush=True)
    with open(args.out, "wb") as f:
        f.write(key)
    open(args.out + ".hex", "w").write(key.hex())
    print(f"  written: {args.out}", flush=True)


if __name__ == "__main__":
    main()
