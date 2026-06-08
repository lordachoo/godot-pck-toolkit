"""
carve_payloads.py — signature-carve Godot payloads straight out of a PCK's
file-data region, WITHOUT the encryption key.

This is the technique that defeats directory-only encryption: even if the file
listing is encrypted, unencrypted file *contents* sit in the pack body and can
be located by their magic bytes (GDSC, RSRC, RSCC, GST2, PNG, OggS, RIFF).

By default it just reports counts (use it as a quick "are my contents exposed?"
check). With --extract it writes the carved blobs out.

For compiled scripts (.gdc), exact blob length is recoverable from the embedded
zstd frame, so extracted .gdc files are clean. For other types the blob is
carved up to the next signature (a superset) and may include trailing bytes.

Usage:
  python carve_payloads.py <exe-or-pck>                 # report only
  python carve_payloads.py <exe-or-pck> --extract out/  # carve blobs to out/
"""
import os
import argparse
import godot_pck_common as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--extract", metavar="DIR", help="carve blobs into this directory")
    ap.add_argument("--types", default="GDSC,RSRC,RSCC,GST2,PNG,OggS,RIFF",
                    help="comma-separated signature names to carve")
    args = ap.parse_args()

    data = open(args.target, "rb").read()
    pck = g.find_embedded_pck_start(data)
    hdr = g.parse_pck_header(data, pck)
    start, end = g.body_region(data, hdr)
    want = [t.strip() for t in args.types.split(",") if t.strip() in g.SIGNATURES]

    print(f"file-data region: [{start}, {end})  = {end - start:,} bytes (no key used)\n")
    all_offsets = {}
    for name in want:
        offs = g.find_magic_offsets(data, g.SIGNATURES[name], start, end)
        all_offsets[name] = offs
        extra = ""
        if name == "GDSC":
            valid = sum(1 for o in offs if g.is_valid_gdc(data, o))
            extra = f"  ({valid} valid compiled scripts, {len(offs) - valid} byte-collisions)"
        print(f"  {name:6} {len(offs)}{extra}")

    if not args.extract:
        print("\n(report only; pass --extract DIR to carve the blobs)")
        return

    out = args.extract
    os.makedirs(out, exist_ok=True)
    n = 0
    for name, offs in all_offsets.items():
        # boundaries: carve each blob up to the next signature of ANY tracked type
        boundaries = sorted(set(o for lst in all_offsets.values() for o in lst) | {end})
        import bisect
        for o in offs:
            nxt = boundaries[bisect.bisect_right(boundaries, o)]
            ext = "gdc" if name == "GDSC" else name.lower()
            blob = data[o:nxt]
            # exact-trim compiled scripts via the self-delimiting zstd frame
            if name == "GDSC" and g.is_valid_gdc(data, o):
                try:
                    blob = blob[:g.gdc_decompress(blob)["exact_len"]]
                except Exception:
                    pass
            fn = os.path.join(out, f"{name}_{o}.{ext}")
            with open(fn, "wb") as f:
                f.write(blob)
            n += 1
    print(f"\ncarved {n} blobs -> {out}")
    print("(.gdc files can be decompiled with Godot RE Tools; see docs/gdre-notes.md)")


if __name__ == "__main__":
    main()
