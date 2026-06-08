# Defender's checklist

A one-page tick-list for hardening a Godot build's content protection. Details in
[`hardening.md`](hardening.md), [`verifying-encryption.md`](verifying-encryption.md),
and [`common-misconfigurations.md`](common-misconfigurations.md).

## Configuration (free, do these first)

- [ ] Custom export templates built from source with `SCRIPT_AES256_ENCRYPTION_KEY`
      (official templates can't encrypt).
- [ ] `encrypt_pck = true` **and** `encrypt_directory = true`.
- [ ] `encryption_include_filters` populated **with leading `*`**:
      `*.gd,*.gdc,*.tscn,*.scn,*.res,*.tres,*.json,*.cfg,*.csv,*.gdshader`
      (`.gd` without the `*` matches nothing).
- [ ] Bulk art (`*.png`, `*.ogg`) left unencrypted for load performance (low value to hide).
- [ ] No server-side/authoritative code shipped in the client export.
- [ ] Genuine secrets (anti-cheat, economy rules, validation) live server-side.
- [ ] `export_presets.cfg` encryption settings are shared across the team
      (committed, with key supplied via env var) — not drifting per-machine.
- [ ] Fresh key generated if any previous key shipped in a cracked build.

## Verify it actually took effect

- [ ] Exported pack **grew** after enabling encryption (it should).
- [ ] `python check_encryption.py build.exe` → **0 valid compiled scripts**.
- [ ] `python pck_compare.py old.exe new.exe` shows scripts went from N → 0.
- [ ] Resource signature counts (`RSRC`, `GST2`) for types you meant to cover dropped.

## Against a runtime attacker (engine-level, bigger effort)

- [ ] Key not held resident as 32 contiguous bytes — split into shares,
      reconstruct into a transient buffer at point of use, secure-wipe after.
- [ ] (Stronger) white-box AES so a discrete key never exists in memory.
- [ ] Sensitive logic moved to native code (GDExtension) — `.gdc` decompiles; C++ doesn't.
- [ ] Optional: commercial packer / anti-debug / anti-dump on the executable.

## Reality check

- Config + verification defeats **automated / no-key / off-the-shelf** attacks. ✔
- Only the engine-level work raises the bar against someone who **runs the client
  and dumps memory** — and even then, client-side protection is never absolute.
