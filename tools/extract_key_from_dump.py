"""
extract_key_from_dump.py — recover the Godot PCK key from a process MEMORY DUMP.

When the key is not stored contiguously on disk (compiled into code as immediate
stores, obfuscated, or runtime-derived), it still exists as a clean contiguous
32-byte block in the RUNNING process's memory. Dump the process, scan the dump.

Verification is exact: a candidate 32-byte window is accepted only if AES-256-
CFB128 decryption of the encrypted directory reproduces the directory's stored
MD5. (That stored MD5 is the build's own self-check; it works as a definitive
oracle for us regardless of what the key value is — so rotating the key does not
help. See docs/memory-key-recovery.md.)

ALIGNMENT — read this, it matters:
  Minidump file offsets do NOT preserve the original RAM alignment, so the
  scanner parses the dump's memory map (Memory64List / MemoryList) and scans
  each region at its TRUE virtual-address alignment.
  The key lives in a Godot Vector/CowData allocation. Godot's allocator prepends
  a size header before the data, so the data pointer is commonly 8-byte aligned,
  NOT 16 — and the exact alignment varies between runs/heap layouts. Empirically
  the key has shown up at both 16- and 8-aligned addresses.
  => Default scan alignment is 8 (covers 8- and 16-aligned). If that misses,
     this falls back to 1 (exhaustive, slower but definitive). Use --align to
     override.

Make a dump (built into Windows, run the game first):
  powershell -File dump_game_memory.ps1 -Exe <game.exe> -Out <game.dmp>

Then:
  python extract_key_from_dump.py <exe-or-pck> <game.dmp> [--align 8] [--out key.bin]
"""
import os
import mmap
import time
import struct
import argparse
import multiprocessing as mp
from Crypto.Cipher import AES

import godot_pck_common as g

_W = {}


def parse_minidump_regions(path):
    """Return [(file_offset, va, size), ...] for all memory regions in a dump.

    Returns None if the file is not a Windows minidump (caller then scans the
    whole file as one region).
    """
    with open(path, "rb") as f:
        head = f.read(32)
        if head[:4] != b"MDMP":
            return None
        nstreams, dir_rva = struct.unpack_from("<II", head, 8)
        f.seek(dir_rva)
        dirs = f.read(nstreams * 12)
        streams = {}
        for i in range(nstreams):
            stype, dsize, rva = struct.unpack_from("<III", dirs, i * 12)
            streams[stype] = (dsize, rva)

        regions = []
        if 9 in streams:  # Memory64ListStream (full-memory dumps)
            _, rva = streams[9]
            f.seek(rva)
            nranges, base_rva = struct.unpack("<QQ", f.read(16))
            desc = f.read(nranges * 16)
            foff = base_rva
            for i in range(nranges):
                va, size = struct.unpack_from("<QQ", desc, i * 16)
                regions.append((foff, va, size))
                foff += size
        elif 5 in streams:  # MemoryListStream (smaller dumps)
            _, rva = streams[5]
            f.seek(rva)
            nranges = struct.unpack("<I", f.read(4))[0]
            desc = f.read(nranges * 16)
            for i in range(nranges):
                # MINIDUMP_MEMORY_DESCRIPTOR: u64 va, u32 DataSize, u32 Rva
                va, dsize, drva = struct.unpack_from("<QII", desc, i * 16)
                regions.append((drva, va, dsize))
        return regions


def _init(dump_path, iv, c0_4, fae):
    f = open(dump_path, "rb")
    _W["mm"] = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    _W["iv"] = iv
    _W["c0_4"] = c0_4
    _W["fae"] = fae


def _scan_region(arg):
    """arg = (file_off, va, size, align). Scan aligned 32-byte windows."""
    file_off, va, size, align = arg
    mm = _W["mm"]; iv = _W["iv"]; c0_4 = _W["c0_4"]; fae = _W["fae"]
    new = AES.new; ECB = AES.MODE_ECB; frombytes = int.from_bytes
    mmlen = len(mm)
    start_va = (va + align - 1) & ~(align - 1)   # first aligned VA in region
    pos = file_off + (start_va - va)
    end = file_off + size - 32
    while pos <= end:
        if pos + 32 > mmlen:                       # boundary guard: no short reads
            break
        key = mm[pos:pos + 32]
        ks = new(key, ECB).encrypt(iv)
        # cheap filter: first CFB block -> first entry's path_len should be sane
        if 1 <= (c0_4 ^ frombytes(ks[:4], "little")) <= 4096:
            if g.verify_key(key, fae) is not None:
                return (pos, key)
        pos += align
    return None


def find_key(exe_path, dump_path, align=8, procs=None):
    data = open(exe_path, "rb").read()
    pck = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])
    iv = fae["iv"]
    c0_4 = int.from_bytes(fae["ciphertext"][:4], "little")
    # Windows WaitForMultipleObjects caps a pool at 63 handles; stay under it.
    procs = min(procs or max(1, os.cpu_count() or 2), 60)

    regions = parse_minidump_regions(dump_path)
    size = os.path.getsize(dump_path)
    if regions is None:
        regions = [(0, 0, size)]
        print("Not a minidump - scanning whole file as one region.", flush=True)
    total_mem = sum(s for _, _, s in regions)
    print(f"dump={size:,}B  regions={len(regions)}  mem={total_mem:,}B  "
          f"procs={procs}  align={align}  md5={fae['md5'].hex()}", flush=True)

    CHUNK = 4 << 20
    tasks = []
    for foff, va, sz in regions:
        o = 0
        while o < sz:
            csz = min(CHUNK, sz - o)
            tasks.append((foff + o, va + o, csz + 32, align))  # +32 overlap
            o += csz
    print(f"{len(tasks)} chunks; ~{total_mem // align:,} candidates", flush=True)

    t0 = time.time()
    done = 0
    with mp.Pool(procs, initializer=_init, initargs=(dump_path, iv, c0_4, fae)) as pool:
        for res in pool.imap_unordered(_scan_region, tasks):
            done += 1
            if res:
                pool.terminate()
                off, key = res
                print(f"HIT at dump offset {off}  ({time.time() - t0:.0f}s)", flush=True)
                return key, off
            if done % 200 == 0:
                print(f"  {done}/{len(tasks)} chunks ({time.time() - t0:.0f}s)", flush=True)
    print(f"no hit at align={align} ({time.time() - t0:.0f}s)", flush=True)
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", help="the game exe/pck (provides the verification oracle)")
    ap.add_argument("dump", help="full-memory dump of the running game")
    ap.add_argument("--align", type=int, default=8,
                    help="scan alignment (default 8; 16 is faster but can miss)")
    ap.add_argument("--out", default="key.bin")
    args = ap.parse_args()

    key, off = find_key(args.exe, args.dump, align=args.align)
    # Fall back to finer alignment if the requested one missed.
    if not key:
        for a in (4, 1):
            if a < args.align:
                print(f"retrying with align={a} ...", flush=True)
                key, off = find_key(args.exe, args.dump, align=a)
                if key:
                    break
    if not key:
        raise SystemExit("Key not found in dump (was the PCK mounted before the dump?).")

    print(f"\nRECOVERED KEY (hex): {key.hex()}", flush=True)
    with open(args.out, "wb") as f:
        f.write(key)
    open(args.out + ".hex", "w").write(key.hex())
    print(f"written {args.out}", flush=True)


if __name__ == "__main__":
    main()
