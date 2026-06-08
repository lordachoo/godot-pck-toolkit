"""
decompile_gdc_batch.py — turn recovered .gdc / .gdef bytecode back into .gd
source using Godot RE Tools (gdsdecomp). Re-implementing a Godot 4.6 bytecode
decompiler is a project in itself, so (as in the reference pipeline) we drive
the maintained GDRE CLI for this one step.

The cleanest path with GDRE is full-project recovery straight from the PCK/EXE,
which also handles decryption if you pass the key. We expose both:

  # A) Let GDRE do the whole recover (decrypt + extract + decompile) from the exe:
  python decompile_gdc_batch.py --gdre <gdre_tools.exe> --recover <exe> \
         --key <hexkey> --out ../recovered/gdre_project

  # B) Just decompile the .gdc files we already extracted ourselves:
  python decompile_gdc_batch.py --gdre <gdre_tools.exe> \
         --decompile-dir ../recovered/project

Get GDRE from: https://github.com/GDRETools/gdsdecomp/releases
"""
import os
import sys
import glob
import argparse
import subprocess


def run(cmd):
    print(">", " ".join(cmd))
    return subprocess.run(cmd).returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gdre", required=True, help="path to gdre_tools.exe")
    ap.add_argument("--recover", help="exe/pck to fully recover")
    ap.add_argument("--key", help="32-byte key as 64 hex chars (for --recover)")
    ap.add_argument("--out", default="../recovered/gdre_project")
    ap.add_argument("--decompile-dir", help="dir of already-extracted .gdc files")
    args = ap.parse_args()

    if args.recover:
        cmd = [args.gdre, "--headless", f"--recover={args.recover}",
               f"--output-dir={args.out}"]
        if args.key:
            cmd.append(f"--key={args.key}")
        sys.exit(run(cmd))

    if args.decompile_dir:
        gdc = glob.glob(os.path.join(args.decompile_dir, "**", "*.gdc"), recursive=True)
        print(f"Found {len(gdc)} .gdc files")
        if not gdc:
            sys.exit("No .gdc files found.")
        # GDRE accepts a comma-separated list to --decompile and a Godot version.
        cmd = [args.gdre, "--headless", "--decompile=" + ",".join(gdc),
               "--output-dir=" + args.decompile_dir]
        sys.exit(run(cmd))

    ap.error("pass --recover or --decompile-dir")


if __name__ == "__main__":
    main()
