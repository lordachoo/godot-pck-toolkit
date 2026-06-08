"""
pck_compare.py — diff two Godot builds (e.g. before/after a hardening change).

Reports side-by-side: data-region size, directory encryption, signature counts,
and valid compiled-script count — so you can see at a glance whether a change
(like enabling per-file encryption) actually took effect.

Tells worth knowing:
  * per-file encryption turns ON  -> valid compiled scripts drop toward 0,
                                     pack body grows (each file gains a header)
  * if nothing changes, the change didn't take effect.

Usage:  python pck_compare.py <build_a> <build_b>
"""
import argparse
import godot_pck_common as g


def snapshot(path):
    data = open(path, "rb").read()
    pck = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])
    start, end = g.body_region(data, hdr)
    total, valid = g.count_valid_scripts(data, hdr)
    return {
        "body": end - start, "dir_enc": hdr["dir_encrypted"],
        "file_count": fae["file_count"], "dir_md5": fae["md5"].hex()[:12],
        "counts": g.carve_counts(data, hdr), "valid_scripts": valid, "total_gdsc": total,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_a")
    ap.add_argument("build_b")
    args = ap.parse_args()
    a, b = snapshot(args.build_a), snapshot(args.build_b)

    def row(label, va, vb):
        delta = ""
        if isinstance(va, int) and isinstance(vb, int):
            d = vb - va
            delta = f"  ({d:+,})" if d else "  (same)"
        print(f"  {label:24} {str(va):>14} {str(vb):>14}{delta}")

    print(f"A = {args.build_a}")
    print(f"B = {args.build_b}\n")
    print(f"  {'metric':24} {'A':>14} {'B':>14}")
    print("  " + "-" * 56)
    row("data region (bytes)", a["body"], b["body"])
    row("file_count", a["file_count"], b["file_count"])
    row("directory encrypted", a["dir_enc"], b["dir_enc"])
    row("dir md5 (head)", a["dir_md5"], b["dir_md5"])
    row("valid compiled scripts", a["valid_scripts"], b["valid_scripts"])
    for name in a["counts"]:
        row(f"sig {name}", a["counts"][name], b["counts"][name])

    print()
    if a["valid_scripts"] > 0 and b["valid_scripts"] == 0:
        print("  => B encrypts script contents that A left in cleartext. Effective.")
    elif a["valid_scripts"] == b["valid_scripts"] and a["body"] == b["body"]:
        print("  => no material difference in content protection between A and B.")
    elif b["valid_scripts"] > 0:
        print(f"  => B still exposes {b['valid_scripts']} compiled scripts in cleartext.")


if __name__ == "__main__":
    main()
