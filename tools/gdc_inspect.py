"""
gdc_inspect.py — inspect a compiled GDScript (.gdc) without a full decompiler.

A compiled script is:  'GDSC' | uint32 version | uint32 decompressed_size | zstd frame
The zstd frame is self-delimiting, so this works even on an over-carved blob and
reports the exact .gdc length. The decompressed tokenizer buffer still contains
identifier names and string literals in cleartext — which is enough to show that
an unencrypted .gdc leaks source-level information even before full decompilation.

Use it to:
  * confirm an unencrypted build leaks readable symbols/strings, and
  * recover the exact length needed for a clean GDRE standalone decompile.

Requires the `zstandard` package.

Usage:
  python gdc_inspect.py <file.gdc> [--strings] [--save-exact out.gdc]
"""
import argparse
import godot_pck_common as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gdc")
    ap.add_argument("--strings", action="store_true", help="print recovered identifiers/literals")
    ap.add_argument("--save-exact", metavar="OUT", help="write the exact-length .gdc (for GDRE)")
    args = ap.parse_args()

    blob = open(args.gdc, "rb").read()
    info = g.gdc_decompress(blob)
    print(f"GDSC version      : {info['version']}")
    print(f"decompressed size : {info['decompressed_size']:,} bytes")
    print(f"exact .gdc length : {info['exact_len']:,} bytes (input was {len(blob):,})")

    if args.save_exact:
        with open(args.save_exact, "wb") as f:
            f.write(blob[:info["exact_len"]])
        print(f"wrote exact-length .gdc -> {args.save_exact}")

    if args.strings:
        ident, lits = g.gdc_readable_strings(info["buffer"])
        print(f"\nidentifiers/symbols ({len(ident)}):")
        print("  " + ", ".join(ident[:60]) + (" ..." if len(ident) > 60 else ""))
        print(f"\nstring literals ({len(lits)}):")
        for s in lits[:40]:
            print("  " + s)
        if len(lits) > 40:
            print(f"  ... (+{len(lits) - 40} more)")


if __name__ == "__main__":
    main()
