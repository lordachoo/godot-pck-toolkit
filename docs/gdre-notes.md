# Using Godot RE Tools (gdsdecomp) with this toolkit

[Godot RE Tools / gdsdecomp](https://github.com/GDRETools/gdsdecomp) ("GDRE") is
the maintained tool for decompiling `.gdc` → `.gd` and converting binary
resources back to text. This toolkit handles the container/crypto half (carve,
key recovery, decrypt); GDRE handles source reconstruction. Notes from practical
use:

## It does NOT bruteforce keys

For an encrypted PCK, GDRE **requires** the key — there's no automatic key
recovery. Without it you get:

```
ERROR: Can't open encrypted pack directory (PCK format version 3, ...)
ERROR: FATAL ERROR: Cannot open encrypted pck! (wrong key?)
```

So an encrypted build blocks GDRE on its own. Recover the key first (statically
with `recover_godot_key.py`, or from a dump with `extract_key_from_dump.py`),
then pass it.

## Full project recovery (with key)

```
gdre_tools.exe --headless --recover=<game.exe-or-.pck> --key=<64-hex> --output=<dir>
```

This extracts, decompiles `.gdc`→`.gd`, and converts resources (`.ctex`→`.png`,
`.scn`→`.tscn`, etc.) in one pass. The `--key` is a 64-character hex string.

## Standalone decompile needs `--bytecode` AND exact-length input

```
gdre_tools.exe --headless --bytecode=<version> --decompile=<file.gdc> --output=<dir>
```

Two gotchas:

1. **`--bytecode` is required** for standalone `--decompile` (use
   `--list-bytecode-versions` to see available revisions). The `--recover` path
   auto-detects it from the pack; standalone does not.
2. **Input must be the exact-length `.gdc`.** An over-carved blob (extra trailing
   bytes) makes the compressed tokenizer buffer fail to decompress
   (`Error decompressing GDScript tokenizer buffer`). Use
   `gdc_inspect.py --save-exact` to trim a carved blob to its true length first.

## Bytecode version availability

GDRE ships definitions for specific engine bytecode revisions. A very new engine
release may not have an exact match yet; GDRE may fall back to the nearest known
revision, which can fail to decompile. If standalone decompile errors on a fresh
engine version, the `--recover` path (with key) is usually more robust, and
`gdc_inspect.py` can still pull identifiers/strings without GDRE at all.

## Where to get it

Releases: https://github.com/GDRETools/gdsdecomp/releases — grab the build for
your platform. This toolkit does not bundle it.

See also: [`gdc-format-notes.md`](gdc-format-notes.md) for the compiled-script
layout and how to recover an exact-length `.gdc` for clean standalone decompile.
