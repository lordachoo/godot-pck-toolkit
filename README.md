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
| `tools/godot_pck_common.py` | Shared PCK (v2/v3) parsing, AES-CFB, and no-key carve/gdc helpers. No side effects. |
| `tools/analyze.py` | **One-shot overview** of a build: header, signatures, encryption verdict. No key. |
| `tools/check_encryption.py` | **Audit** whether per-file encryption actually protects contents. No key. |
| `tools/carve_payloads.py` | Signature-carve payloads (GDSC/RSRC/…) from the pack body. No key. |
| `tools/gdc_inspect.py` | Decompress a compiled `.gdc`, recover exact length + readable symbols/strings. |
| `tools/pck_compare.py` | Diff two builds (before/after a hardening change). No key. |
| `tools/extract_godot_pck.py` | Carve the embedded PCK from a PE executable + dump a header report. No key. |
| `tools/recover_godot_key.py` | Brute-force the 32-byte AES key from the executable, verified against the directory MD5. |
| `tools/extract_key_from_dump.py` | Recover the key from a process **memory dump** (minidump-aware, multi-core, alignment-aware). |
| `tools/find_aes_rvas.py` | **Static, no-spawn:** locate the mbedtls AES-NI key-setup entries in a PE (and tell you if the build has *no* AES-NI cluster to hook). |
| `tools/frida_keycatch.py` | Recover the key by **hooking the AES routine at runtime** — defeats "wipe the key after use" hardening (needs `frida`). Handles embedded *and* separate `.pck`. See [frida-key-hooking.md](docs/frida-key-hooking.md). |
| `tools/dump_game_memory.ps1` | Launch a game, let it mount its PCK, write a full-memory minidump, kill it. |
| `tools/extract_godot_project.py` | Decrypt the directory and extract + per-file-decrypt every asset. |
| `tools/decompile_gdc_batch.py` | Drive Godot RE Tools to decompile `.gdc`→`.gd` / full project recovery. |

## Quickstart

**Prefer a menu?** Run [`run.sh`](run.sh) (bash/Linux/macOS/Git-Bash) or
[`run.bat`](run.bat) (Windows) for an interactive front-end over all of the
below — set a target once and pick actions from a list.

```bash
pip install -r requirements.txt
cd tools

# 0) Quick no-key overview + encryption verdict (start here)
python analyze.py /path/to/your_game.exe
python check_encryption.py /path/to/your_game.exe

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

#    If the key is wiped right after use (a dump finds nothing), catch it at the
#    moment of use by hooking the AES routine (needs frida):
python find_aes_rvas.py /path/to/your_game.exe          # confirm there's an AES-NI cluster
python frida_keycatch.py /path/to/your_game.exe         # spawn + hook + verify

# 3) Decrypt the directory and extract everything
python extract_godot_project.py /path/to/your_game.exe --key ../out/key.bin --out ../out/project

# 4) (optional) Decompile .gdc -> .gd with GDRE
python decompile_gdc_batch.py --gdre /path/to/gdre_tools.exe --recover /path/to/your_game.exe --key <hex> --out ../out/recovered
```

## Documentation

- [`docs/how-pck-encryption-works.md`](docs/how-pck-encryption-works.md) — the PCK format, the crypto, and the full recovery methodology
- [`docs/memory-key-recovery.md`](docs/memory-key-recovery.md) — recovering the key from a memory dump, the "oracle", and **alignment handling**
- [`docs/verifying-encryption.md`](docs/verifying-encryption.md) — how to confirm your encryption actually took effect
- [`docs/common-misconfigurations.md`](docs/common-misconfigurations.md) — the frequent mistakes (missing `*`, directory-only, etc.)
- [`docs/gdc-format-notes.md`](docs/gdc-format-notes.md) — compiled `.gdc` layout, exact-length carving, magic collisions
- [`docs/gdre-notes.md`](docs/gdre-notes.md) — using Godot RE Tools (`--bytecode`, exact-length, no key bruteforce)
- [`docs/hardening.md`](docs/hardening.md) — how to make all of the above harder (the defensive playbook)
- [`docs/post-wipe-attack-surface.md`](docs/post-wipe-attack-surface.md) — the rung *above* a memory dump: runtime hooking / TTD / offline shares, and the counters
- [`docs/frida-key-hooking.md`](docs/frida-key-hooking.md) — step-by-step runtime key hooking with `find_aes_rvas.py` + `frida_keycatch.py`, **with example output** and the "when it finds nothing" diagnosis
- [`docs/defenders-checklist.md`](docs/defenders-checklist.md) — one-page hardening tick-list
- [`hardening/`](hardening/) — **reference patches** for Godot 4.6.1-stable: secure-wipe the PCK key + split-key storage, with verification steps

## License

MIT — see [`LICENSE`](LICENSE).
