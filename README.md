# godot-pck-toolkit

Carve, key-recover, decrypt, and extract **Godot** `.pck` archives — and the
defensive research to understand how to harden against it.

This is a reverse-engineering / security-research toolkit for Godot 4.x
self-contained exports (and standalone `.pck` files), including builds that use
Godot's optional **AES-256 PCK encryption**. It documents and reproduces the full
recovery pipeline: locate the embedded PCK, recover the encryption key (by static
scan *or* from a process memory dump), decrypt the directory, and extract every
file. A companion guide covers how to make all of that harder.

> ⚠️ **Authorized use only.** Use this strictly on software **you own** or are
> **explicitly authorized to analyze** (your own games, security research with
> permission, CTFs, interoperability/preservation of your own work). Extracting
> or redistributing assets/code from games you don't own may violate copyright
> and the software's license/EULA. You are responsible for how you use this.

## Why this exists

Godot's PCK encryption is widely misunderstood. Teams enable "encryption" and
assume their content is safe, when in practice:

- The **embedded PCK is trivially carved** out of the executable (no key needed).
- **Directory-only encryption** leaves file *contents* in plaintext, recoverable
  by signature carving without any key.
- The AES key, even when not stored as contiguous bytes on disk, **exists in
  process memory at runtime** and is recoverable with a memory dump.

This toolkit demonstrates each step so developers can see exactly what an attacker
sees — then [`docs/hardening.md`](docs/hardening.md) explains what actually helps.

## Requirements

- Python 3.10+
- `pip install pycryptodome numpy`
- Windows for the memory-dump helper (`dump_game_memory.ps1`); the rest is cross-platform
- [Godot RE Tools (gdsdecomp)](https://github.com/GDRETools/gdsdecomp) for `.gdc`→`.gd` decompilation (optional)

## Tools

| Script | Purpose |
|---|---|
| `tools/godot_pck_common.py` | Shared PCK (v2/v3) parsing + AES-CFB helpers. No side effects. |
| `tools/extract_godot_pck.py` | Carve the embedded PCK from a PE executable + dump a header report. No key needed. |
| `tools/recover_godot_key.py` | Brute-force the 32-byte AES key from the executable, verified against the directory MD5. |
| `tools/extract_key_from_dump.py` | Recover the key from a process **memory dump** (minidump-aware, multi-core). |
| `tools/dump_game_memory.ps1` | Launch a game, let it mount its PCK, write a full-memory minidump, kill it. |
| `tools/extract_godot_project.py` | Decrypt the directory and extract + per-file-decrypt every asset. |
| `tools/decompile_gdc_batch.py` | Drive Godot RE Tools to decompile `.gdc`→`.gd` / full project recovery. |

## Quickstart

```bash
pip install pycryptodome numpy
cd tools

# 1) Carve the embedded PCK and print a header report (no key required)
python extract_godot_pck.py /path/to/your_game.exe --outdir ../out

# 2) Try to recover the key statically from the executable
python recover_godot_key.py /path/to/your_game.exe --out ../out/key.bin

#    If that fails (common — the key is often only assembled at runtime),
#    recover it from a memory dump instead:
#    (Windows) launch + dump:
powershell -ExecutionPolicy Bypass -File dump_game_memory.ps1 `
    -Exe C:\path\to\your_game.exe -Out C:\path\to\game.dmp
python extract_key_from_dump.py /path/to/your_game.exe /path/to/game.dmp --out ../out/key.bin

# 3) Decrypt the directory and extract everything
python extract_godot_project.py /path/to/your_game.exe --key ../out/key.bin --out ../out/project

# 4) (optional) Decompile .gdc -> .gd with GDRE
python decompile_gdc_batch.py --gdre /path/to/gdre_tools.exe --recover /path/to/your_game.exe --key <hex> --out ../out/recovered
```

## Documentation

- [`docs/how-pck-encryption-works.md`](docs/how-pck-encryption-works.md) — the PCK format, the crypto, and the full recovery methodology
- [`docs/hardening.md`](docs/hardening.md) — how to make all of the above harder (the defensive playbook)

## License

MIT — see [`LICENSE`](LICENSE).
