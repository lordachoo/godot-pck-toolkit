"""
check_encryption.py — audit whether a Godot build's PCK encryption is actually
protecting file contents. No key required.

Godot has two independent encryption layers:
  * directory/index encryption  (encrypt_directory)  -> hides the file listing
  * per-file content encryption  (encrypt_pck + encryption_include_filters)
                                                      -> encrypts the file bytes

A very common misconfiguration enables only the directory (or sets include
filters that match nothing), leaving every file's bytes in cleartext inside the
pack — recoverable by content carving with no key. This tool tells you which
layers are really active by looking at what's still carve-able.

Usage:  python check_encryption.py <exe-or-pck>
"""
import sys
import argparse
import godot_pck_common as g


def audit(path: str) -> dict:
    data = open(path, "rb").read()
    pck = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])
    counts = g.carve_counts(data, hdr)
    total_gdsc, valid_scripts = g.count_valid_scripts(data, hdr)
    body_start, body_end = g.body_region(data, hdr)
    return {
        "path": path, "godot": hdr["godot"], "version": hdr["version"],
        "dir_encrypted": hdr["dir_encrypted"], "flags": hdr["flags"],
        "file_count": fae["file_count"], "body_bytes": body_end - body_start,
        "counts": counts, "total_gdsc": total_gdsc, "valid_scripts": valid_scripts,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="game .exe or .pck")
    args = ap.parse_args()
    a = audit(args.target)

    print(f"target        : {a['path']}")
    print(f"godot         : {a['godot'][0]}.{a['godot'][1]}.{a['godot'][2]}  (pack v{a['version']})")
    print(f"files         : {a['file_count']}")
    print(f"pack_flags    : {a['flags']}  (directory {'ENCRYPTED' if a['dir_encrypted'] else 'plaintext'})")
    print(f"data region   : {a['body_bytes']:,} bytes")
    print("\nsignatures still visible in the file-data region (no key):")
    for name, c in a["counts"].items():
        print(f"   {name:6} {c}")

    print("\n--- script content ---")
    print(f"   GDSC magics: {a['total_gdsc']}   valid compiled scripts: {a['valid_scripts']}")
    if a["valid_scripts"] == 0:
        print("   [OK]   scripts appear ENCRYPTED (no carve-able compiled scripts found)")
    else:
        print(f"   [LEAK] scripts appear PLAINTEXT - {a['valid_scripts']} compiled scripts are")
        print("          directly recoverable WITHOUT the key (content carving).")

    print("\n--- verdict ---")
    if not a["dir_encrypted"] and a["valid_scripts"] > 0:
        print("   NO meaningful encryption: directory plaintext AND contents carve-able.")
    elif a["dir_encrypted"] and a["valid_scripts"] > 0:
        print("   DIRECTORY-ONLY encryption: index is locked but file CONTENTS are")
        print("   cleartext and carve-able without a key. Populate encryption_include_filters")
        print("   with glob patterns (e.g. *.gd,*.gdc,*.tscn,*.scn,*.res,*.tres,*.json).")
        print("   NOTE: patterns need the leading '*' — '.gd' matches nothing, '*.gd' works.")
    else:
        print("   Per-file content encryption is active for scripts. Good.")
        print("   (Resources/other types may still be partially unencrypted - check the")
        print("    RSRC/GST2 counts above against what you intended to cover.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
