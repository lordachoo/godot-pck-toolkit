# Verifying your PCK encryption actually works

Enabling encryption in the export dialog is not proof it took effect. A
misconfiguration can leave your file contents in cleartext while *looking*
encrypted. Here's how to verify objectively, with no key.

## The two-second test: did the pack grow?

Turning on **per-file content encryption** wraps each matching file in a small
header (md5 + length + iv) and pads it to a 16-byte boundary. So the exported
`.pck`/exe **grows** — by roughly `(#encrypted files) × (~40 bytes + padding)`.

- Pack got **bigger** after enabling encryption → file encryption is doing
  *something*.
- Pack **same size or smaller** → **no files are being encrypted.** Stop and fix
  the config before anything else (see [`common-misconfigurations.md`](common-misconfigurations.md)).

## The objective test: are scripts still carve-able?

Compiled scripts start with the `GDSC` magic. If their contents are encrypted,
that magic becomes ciphertext and disappears. Run:

```bash
python check_encryption.py path/to/game.exe
```

Look at **"valid compiled scripts"**:

- `valid compiled scripts: 0` → scripts are encrypted. ✔
- `valid compiled scripts: N (>0)` → N scripts are sitting in cleartext and are
  recoverable with **no key** by content carving. ✗

(The tool distinguishes *valid* compiled scripts — `GDSC` + version + zstd frame
— from coincidental `GDSC` byte sequences inside other data, so the count is
meaningful.)

## Before/after a change

```bash
python pck_compare.py old_build.exe new_build.exe
```

Side-by-side size + signature counts + valid-script count. If you "enabled
encryption" but the diff shows no change, it didn't take effect.

## Prove the exposure (optional)

To see exactly what leaks from an unencrypted build:

```bash
python carve_payloads.py game.exe --extract carved/      # pull blobs out, no key
python gdc_inspect.py carved/GDSC_<n>.gdc --strings      # readable symbols/strings
```

## What "good" looks like

- Pack size grew after enabling encryption.
- `check_encryption.py` reports **0 valid compiled scripts**.
- `RSRC`/`GST2` counts for resource types you intended to cover have dropped too.
- Directory is encrypted (so a clean *named* extraction also needs the key).

Remember: passing all of the above defeats **no-key / automated** attacks. It
does **not** stop someone who runs the client and dumps memory — that requires
engine-level key hardening (see [`hardening.md`](hardening.md) and
[`memory-key-recovery.md`](memory-key-recovery.md)).
