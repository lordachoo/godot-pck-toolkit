"""
analyze.py — one-shot overview of a Godot build's PCK.

Runs the no-key analysis in a single command: locate + parse the PCK header,
show the directory/encryption status, count carve-able signatures, and give an
encryption verdict. A friendly entry point that ties the individual tools
together. No key required.

Usage:  python analyze.py <exe-or-pck>
"""
import argparse
import godot_pck_common as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    args = ap.parse_args()

    data = open(args.target, "rb").read()
    pck = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])
    start, end = g.body_region(data, hdr)
    counts = g.carve_counts(data, hdr)
    total_gdsc, valid = g.count_valid_scripts(data, hdr)

    print("=" * 60)
    print(f" {args.target}")
    print("=" * 60)
    print(f" file size        : {len(data):,} bytes")
    print(f" embedded PCK at  : {pck:,}")
    print(f" godot / pack ver : {hdr['godot'][0]}.{hdr['godot'][1]}.{hdr['godot'][2]} / v{hdr['version']}")
    print(f" pack_flags       : {hdr['flags']}  "
          f"(dir_encrypted={hdr['dir_encrypted']}, rel_filebase={hdr['rel_filebase']}, "
          f"sparse={hdr['sparse_bundle']})")
    print(f" file_count       : {fae['file_count']}")
    print(f" data region      : {end - start:,} bytes")
    print(f" dir blob md5     : {fae['md5'].hex()}")

    print("\n carve-able signatures (no key):")
    for name, c in counts.items():
        print(f"   {name:6} {c}")

    print("\n script protection:")
    print(f"   GDSC magics={total_gdsc}  valid compiled scripts={valid}")
    if valid == 0:
        print("   => scripts ENCRYPTED (none carve-able)")
    else:
        print(f"   => scripts PLAINTEXT ({valid} recoverable with no key)")

    print("\n next steps:")
    if hdr["dir_encrypted"]:
        print("   - directory is encrypted: a clean named extraction needs the key")
        print("     (recover_godot_key.py from the exe, or extract_key_from_dump.py from a dump)")
    if valid > 0:
        print("   - contents are carve-able now: carve_payloads.py --extract")
    print("   - see check_encryption.py for a focused defender-oriented verdict")


if __name__ == "__main__":
    main()
