"""
Shared helpers for the Godot PCK recovery pipeline.

Target: a Godot 4.x self-contained Windows export (.exe) with an embedded,
encrypted PCK (pack format version 3). Educational use on your own game.

PCK format v3 (see godot core/io/file_access_pack.cpp):

    [PE executable bytes ...]
    GDPC                         embedded-PCK start magic (also at EOF trailer)
    uint32  pack_format_version  == 3
    uint32  ver_major            (4)
    uint32  ver_minor            (6)
    uint32  ver_patch
    uint32  pack_flags           bit0 PACK_DIR_ENCRYPTED, bit1 PACK_REL_FILEBASE,
                                 bit2 PACK_SPARSE_BUNDLE
    uint64  file_base            (+= pck_start in v3) base for every entry offset
    uint64  dir_offset           (+= pck_start in v3) where the directory lives
    [ reserved / file data ... ]

At dir_offset:
    uint32  file_count           PLAINTEXT (read before the encryption wrapper)
    --- FileAccessEncrypted blob (no magic), present iff PACK_DIR_ENCRYPTED ---
    byte[16] md5                 MD5 of the plaintext entries
    uint64   length              plaintext length of the entries blob
    byte[16] iv                  AES-CFB IV
    byte[]   ciphertext          AES-256-CFB128(entries), padded to 16 bytes

Each entry (after decryption):
    uint32   path_len
    byte[]   path                UTF-8, e.g. "res://scenes/main.tscn"
    uint64   ofs                 file data offset, actual = file_base + ofs
    uint64   size
    byte[16] md5
    uint32   flags               bit0 PACK_FILE_ENCRYPTED

The EOF trailer (last 12 bytes) is: uint64 embedded_size, then 'GDPC'.
"""
import struct
import hashlib
from Crypto.Cipher import AES

PACK_MAGIC = b"GDPC"
PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE  = 1 << 1
PACK_SPARSE_BUNDLE = 1 << 2
PACK_FILE_ENCRYPTED = 1 << 0


def find_embedded_pck_start(data: bytes) -> int:
    """Locate the embedded PCK using the EOF trailer: [u64 size]['GDPC']."""
    if data[-4:] == PACK_MAGIC:
        embedded_size = struct.unpack_from("<Q", data, len(data) - 12)[0]
        start = len(data) - embedded_size - 12
        if data[start:start + 4] == PACK_MAGIC:
            return start
    # Fallback: last standalone GDPC occurrence.
    idx = data.rfind(PACK_MAGIC, 0, len(data) - 4)
    if idx == -1:
        raise ValueError("No embedded GDPC PCK found in file.")
    return idx


def parse_pck_header(data: bytes, pck_start: int) -> dict:
    o = pck_start
    magic, version, vmaj, vmin, vpatch, flags = struct.unpack_from("<4sIIIII", data, o)
    if magic != PACK_MAGIC:
        raise ValueError("Bad PCK magic at %d" % pck_start)
    o += 24
    file_base = struct.unpack_from("<Q", data, o)[0]
    o += 8
    dir_offset_raw = struct.unpack_from("<Q", data, o)[0]  # v3 only
    if version == 3:
        file_base += pck_start
        dir_offset = dir_offset_raw + pck_start
    else:
        # v2: directory immediately after header (+16 reserved u32)
        dir_offset = pck_start + 24 + 8 + (16 * 4)
        if flags & PACK_REL_FILEBASE:
            file_base += pck_start
    return {
        "version": version,
        "godot": (vmaj, vmin, vpatch),
        "flags": flags,
        "dir_encrypted": bool(flags & PACK_DIR_ENCRYPTED),
        "rel_filebase": bool(flags & PACK_REL_FILEBASE),
        "sparse_bundle": bool(flags & PACK_SPARSE_BUNDLE),
        "file_base": file_base,
        "dir_offset": dir_offset,
        "pck_start": pck_start,
    }


def read_dir_fae_header(data: bytes, dir_offset: int) -> dict:
    """Read the plaintext file_count and the FileAccessEncrypted blob header."""
    file_count = struct.unpack_from("<I", data, dir_offset)[0]
    o = dir_offset + 4
    md5 = data[o:o + 16]; o += 16
    length = struct.unpack_from("<Q", data, o)[0]; o += 8
    iv = data[o:o + 16]; o += 16
    ct_start = o
    ct_len = (length + 15) & ~15  # round up to AES block
    ciphertext = data[ct_start:ct_start + ct_len]
    return {
        "file_count": file_count,
        "md5": md5,
        "length": length,
        "iv": iv,
        "ct_start": ct_start,
        "ciphertext": ciphertext,
    }


def aes_cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CFB with 128-bit segments (matches Godot/mbedtls cfb128)."""
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ciphertext)


def verify_key(key: bytes, fae: dict) -> bytes | None:
    """Full decrypt + MD5 check. Returns plaintext entries blob on success."""
    pt = aes_cfb_decrypt(key, fae["iv"], fae["ciphertext"])[:fae["length"]]
    if hashlib.md5(pt).digest() == fae["md5"]:
        return pt
    return None


def parse_entries(plaintext: bytes, file_count: int, file_base: int) -> list:
    entries = []
    o = 0
    for _ in range(file_count):
        sl = struct.unpack_from("<I", plaintext, o)[0]; o += 4
        path = plaintext[o:o + sl].split(b"\x00")[0].decode("utf-8", "replace"); o += sl
        ofs, size = struct.unpack_from("<QQ", plaintext, o); o += 16
        md5 = plaintext[o:o + 16]; o += 16
        flags = struct.unpack_from("<I", plaintext, o)[0]; o += 4
        entries.append({
            "path": path,
            "data_offset": file_base + ofs,
            "size": size,
            "md5": md5,
            "encrypted": bool(flags & PACK_FILE_ENCRYPTED),
            "flags": flags,
        })
    return entries
