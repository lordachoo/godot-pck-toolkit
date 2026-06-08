# Common Godot PCK encryption misconfigurations

Real, frequently-seen mistakes that make "encrypted" builds far weaker than the
developer thinks. Each is detectable with `check_encryption.py` (no key) — see
[`verifying-encryption.md`](verifying-encryption.md) for the verification workflow.

## 1. Filters missing the `*` wildcard  ← the classic

```ini
encryption_include_filters=".gd,.gdc,.tscn,.scn,.res"      # WRONG — matches nothing
encryption_include_filters="*.gd,*.gdc,*.tscn,*.scn,*.res" # RIGHT
```

Godot matches these patterns as **globs against the full resource path**
(e.g. `res://scripts/main.gd`). `.gd` is a literal — it only matches a file whose
path is exactly `.gd`, which never exists. Result: **zero files encrypted**, even
though `encrypt_pck=true`. Symptom: pack doesn't grow; scripts still carve-able.

## 2. Empty include filters → directory-only encryption

`encrypt_pck=true` + `encrypt_directory=true` but **empty**
`encryption_include_filters` encrypts only the **index**, not file **contents**.
The file listing is hidden, but every file's bytes are cleartext in the pack and
recoverable by content carving without a key. Directory encryption alone is weak.

## 3. Confusing the two encryption layers

| Setting | Encrypts | Stops |
|---|---|---|
| `encrypt_directory` | the file listing (paths/offsets/sizes) | clean *named* extraction without the key |
| `encrypt_pck` + include filters | the file **contents** | content carving of those files |

You want **both**. Directory encryption without content encryption is the most
common false sense of security.

## 4. Shipping server-side code in the client

Including server-side logic (e.g. a `server/` scripts folder) in the client
export ships your authoritative/anti-cheat code to every player. Encryption
doesn't fix the design problem — and if encryption is also misconfigured, it's
plaintext.
Keep genuine secrets server-side; exclude server code from client export filters.

## 5. Forgetting that custom templates are required

Official export templates **cannot** encrypt — the key is omitted from them. PCK
encryption requires **custom export templates compiled from source** with
`SCRIPT_AES256_ENCRYPTION_KEY` set. If you enable encryption while still pointing
at stock templates, the export fails or doesn't encrypt.

## 6. `export_presets.cfg` is git-ignored by default

Many projects git-ignore `export_presets.cfg`, so **encryption settings don't
sync between developers**. One person's "it's set to true" never reaches another's
machine via pull. Either commit the file (and keep the key in the
`GODOT_SCRIPT_ENCRYPTION_KEY` env var, not in the file), or document the required
settings out-of-band.

## 7. Reusing a leaked key

If a key has ever shipped in a build that was cracked, treat it as public.
Generate a new one (`openssl rand -hex 32`), rebuild the custom templates with it,
and re-export. The recovery oracle (the directory MD5) means a known key opens the
build instantly.

## 8. Expecting source-level obfuscators to "just work"

GDScript obfuscator addons are export-pipeline- and engine-version-sensitive:
they need the right script export mode so they receive raw `.gd`, and an
addon that's outdated for your engine version may silently fail to load (so it
obfuscates nothing) or break the build. Always verify on the **exported** build
that identifiers are actually mangled — don't assume.

## 9. Believing per-file encryption defeats memory dumping

It doesn't. Per-file encryption defeats *no-key* attacks (carving, static
tooling). The key still lives in RAM at runtime and is recoverable from a memory
dump in seconds. Closing that requires engine-level key hardening — see
[`hardening.md`](hardening.md).
