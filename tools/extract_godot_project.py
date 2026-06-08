"""
extract_godot_project.py — using the recovered key, decrypt the PCK directory,
parse all entries, and extract every file (decrypting per-file encrypted blobs).

Per-file encrypted entries are FileAccessEncrypted blobs (no magic), identical
in layout to the directory blob: md5(16) | length(8) | iv(16) | AES-CFB128 ct.
For those, the directory 'size' is the on-disk (encrypted) blob size.

Usage:
  python extract_godot_project.py <exe> --key recovered/key.bin --out recovered/project
"""
import os
import json
import struct
import hashlib
import argparse
import godot_pck_common as g


def decrypt_file_blob(blob: bytes, key: bytes) -> bytes:
    md5 = blob[:16]
    length = struct.unpack_from("<Q", blob, 16)[0]
    iv = blob[24:40]
    ct = blob[40:]
    ct = ct[:((length + 15) & ~15)]
    pt = g.aes_cfb_decrypt(key, iv, ct)[:length]
    if hashlib.md5(pt).digest() != md5:
        raise ValueError("per-file MD5 mismatch (bad key or corrupt entry)")
    return pt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--key", default="../recovered/key.bin")
    ap.add_argument("--out", default="../recovered/project")
    args = ap.parse_args()

    data = open(args.exe, "rb").read()
    key = open(args.key, "rb").read()
    assert len(key) == 32, "key must be 32 bytes"

    pck_start = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck_start)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])

    plaintext = g.verify_key(key, fae)
    if plaintext is None:
        raise SystemExit("Key does not decrypt the directory (MD5 mismatch).")
    entries = g.parse_entries(plaintext, fae["file_count"], hdr["file_base"])
    print(f"Directory decrypted OK. {len(entries)} entries.")

    os.makedirs(args.out, exist_ok=True)
    manifest = []
    n_enc = n_plain = n_bad = 0
    for e in entries:
        rel = e["path"]
        for pre in ("res://", "user://"):
            if rel.startswith(pre):
                rel = rel[len(pre):]
        rel = rel.lstrip("/").replace("\\", "/")
        dst = os.path.join(args.out, *rel.split("/"))
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

        raw = data[e["data_offset"]:e["data_offset"] + e["size"]]
        status = "ok"
        try:
            content = decrypt_file_blob(raw, key) if e["encrypted"] else raw
            if e["encrypted"]:
                n_enc += 1
            else:
                n_plain += 1
                # plaintext entries carry an MD5 of the content; verify when set
                if e["md5"] != b"\x00" * 16 and hashlib.md5(content).digest() != e["md5"]:
                    status = "md5-warn"
        except Exception as ex:
            n_bad += 1
            status = "ERROR: %s" % ex
            content = raw
        with open(dst, "wb") as f:
            f.write(content)
        manifest.append({"path": e["path"], "out": dst, "encrypted": e["encrypted"],
                         "size": e["size"], "status": status})

    json.dump(manifest, open(os.path.join(os.path.dirname(args.out), "manifest.json"), "w"), indent=2)
    print(f"Extracted {len(entries)} files -> {args.out}")
    print(f"  encrypted: {n_enc}   plaintext: {n_plain}   errors: {n_bad}")
    exts = {}
    for e in entries:
        ext = os.path.splitext(e["path"])[1].lower()
        exts[ext] = exts.get(ext, 0) + 1
    top = sorted(exts.items(), key=lambda kv: -kv[1])[:15]
    print("Top extensions: " + ", ".join(f"{k or '<none>'}={v}" for k, v in top))


if __name__ == "__main__":
    main()
