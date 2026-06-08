# How Godot PCK encryption works — and how it's recovered

A technical walkthrough of the Godot `.pck` container, its optional AES-256
encryption, and the end-to-end recovery methodology this toolkit automates.
Everything here is derived from the public Godot engine source
(`core/io/file_access_pack.cpp`, `core/io/file_access_encrypted.cpp`).

> Authorized use only — analyze software you own or are permitted to analyze.

## 1. The container

A Godot game ships its assets in a PCK archive. With a self-contained export, the
PCK is **appended to the executable** and the file ends with a trailer:

```
[ PE executable bytes ... ][ PCK ][ uint64 embedded_size ][ 'GDPC' ]
```

So the PCK can always be **located and carved without any key** — read the last
12 bytes, get the size, seek back. Standalone `.pck` files simply start with the
`GDPC` magic at offset 0.

### PCK header (format v3)

```
'GDPC'                        magic
uint32  pack_format_version   == 3   (v2 also supported)
uint32  ver_major / minor / patch
uint32  pack_flags            bit0 PACK_DIR_ENCRYPTED
                              bit1 PACK_REL_FILEBASE  (always set in v3)
                              bit2 PACK_SPARSE_BUNDLE
uint64  file_base             base added to every entry offset
uint64  dir_offset            (v3) where the directory lives; v2 puts it after the header
```

### The directory

At `dir_offset`:

```
uint32  file_count            <-- PLAINTEXT (read before any encryption wrapper)
--- if PACK_DIR_ENCRYPTED: a FileAccessEncrypted blob (no magic) ---
byte[16] md5(plaintext)       MD5 of the decrypted directory entries
uint64   length               plaintext length of the entries
byte[16] iv                   AES-CFB IV (random per export)
byte[]   ciphertext           AES-256-CFB128(entries)
```

Each entry (after decryption):

```
uint32   path_len
byte[]   path                 e.g. "res://scenes/main.tscn"
uint64   ofs                  actual data position = file_base + ofs
uint64   size
byte[16] md5
uint32   flags                bit0 PACK_FILE_ENCRYPTED
```

## 2. The crypto

Godot uses **AES-256 in CFB mode with 128-bit segments** (mbedtls `cfb128`); the
encrypt key schedule is used for both directions. Per-file encrypted entries use
the *identical* FileAccessEncrypted layout (`md5 | length | iv | ciphertext`), and
for those the directory `size` is the on-disk (encrypted) blob size.

Everything hinges on one 32-byte secret: the **script-encryption key**
(`GODOT_SCRIPT_ENCRYPTION_KEY`, a 64-hex-char string at export time). To use PCK
encryption you must compile **custom export templates** from source with
`SCRIPT_AES256_ENCRYPTION_KEY` set, because the official templates omit it.

## 3. Two independent encryption layers (this trips people up)

| Layer | Setting | What it protects |
|---|---|---|
| **Directory / index** | `encrypt_directory` → `PACK_DIR_ENCRYPTED` | the *catalog* (paths, offsets, sizes) — **not** file bytes |
| **File contents** | `encrypt_pck` **+** `encryption_include_filters` → per-entry `PACK_FILE_ENCRYPTED` | the actual *bytes* of matching files |

A critical, common misconfiguration: `encrypt_pck=true` with an **empty**
`encryption_include_filters`. The result is **directory-only** encryption — the
index is locked but **every file is stored in plaintext**. An attacker doesn't
even need the key: they **signature-carve** the pack body for known magics
(`GDSC` for compiled scripts, `RSRC`/`RSCC` for resources, `\x89PNG`, `OggS`, …)
and pull files straight out.

A quick self-check: turning on real per-file encryption makes the pack
**~1–2 MB bigger** (each encrypted file gains a ~40-byte header + padding). If the
pack size doesn't grow after you "enable encryption," it isn't actually on.

## 4. Recovering the key

### 4a. Static recovery (often fails — that's expected)

Brute-force every 32-byte window of the executable, accepting a candidate only
if AES-256-CFB decryption of the directory reproduces the stored MD5 (a definitive
oracle). A cheap first-block filter (does the first entry's `path_len` look sane?)
avoids full decryption on most candidates.

This frequently finds **nothing**, because the key is often *not* stored as
contiguous bytes on disk — compilers may materialize the key array via immediate
instructions scattered through `.text`, or it's assembled at runtime. A complete
negative static scan is itself a useful result: it means the build resists naive
static extraction.

### 4b. Memory recovery (the reliable route)

The engine **must** hold the cleartext key in RAM to mount the PCK at startup, so:

1. Run the game; it mounts/decrypts the PCK during engine init (before the main
   scene, before networking).
2. Take a full-memory dump (`MiniDumpWriteDump` — no admin needed for a same-user
   process).
3. Scan the dump for a 32-byte window that satisfies the directory MD5.

Note: minidump **file offsets do not preserve RAM alignment**, so a blind
file-offset-aligned scan misses the key. The scanner parses the dump's memory map
(`Memory64List` / `MemoryList`) and scans each region at its **true virtual-address
alignment** (heap allocations are 16-byte aligned), which both finds the key and
cuts the search ~16×.

This route is **format- and obfuscation-agnostic**: no matter how the key is
hidden on disk, the running process must reconstruct it.

## 5. Extraction

With the key:

1. Decrypt the directory blob (verify against its MD5).
2. Parse entries; for each, read `size` bytes at `file_base + ofs`.
3. If `PACK_FILE_ENCRYPTED`, the bytes are a FileAccessEncrypted blob — decrypt
   and verify per-file MD5. Otherwise they're already plaintext.
4. Write files out under their `res://` paths.

Then optionally decompile `.gdc` → `.gd` and convert binary resources with
[Godot RE Tools](https://github.com/GDRETools/gdsdecomp).

## 6. Takeaways for defenders

- Carving the container needs no key — encryption is what matters.
- **Directory-only encryption is weak** — content carving walks straight past it.
  Encrypt the *contents* of sensitive files via include filters.
- The key lives in memory at runtime; a memory dump recovers it in seconds unless
  the build specifically hardens key handling.

See [`hardening.md`](hardening.md) for how to raise each of these bars.
