# Hardening Godot against PCK extraction

How to make the recovery pipeline in [`how-pck-encryption-works.md`](how-pck-encryption-works.md)
as expensive as possible. This is defense-in-depth, not a lock.

## The honest threat model

Client-side content protection can never be absolute — the client must hold the
cleartext to run, so a determined human with a debugger can always get there
(the "analog hole" of DRM). Realistic goals, in order:

1. **Defeat automated / turnkey attacks** (off-the-shelf extractors, static
   scanners, "dump-and-grep" scripts). *Very achievable.*
2. **Force deep manual reverse engineering** (hours of expert effort, not a
   60-second script). *Achievable.*
3. **Make the payoff not worth the cost.** *The real win condition.*

## The attacker's kill chain — break any link

| # | Link | What enables it | Counter |
|---|---|---|---|
| A | Get a memory dump | `MiniDumpWriteDump` works with no admin (same-user) | anti-dump / anti-debug / packer / higher integrity |
| B | Key is 32 contiguous bytes in the heap | stock engine keeps the AES key resident all session | split-key + microsecond reconstruct + secure-wipe, or white-box AES |
| C | Verify a guess instantly | the PCK stores `md5(plaintext directory)` — a perfect offline oracle | custom container without a known-plaintext checksum |

**Link B is the highest-value target.** With no persistent contiguous key, the
"scan the dump for 32 verifiable bytes" technique collapses regardless of how easy
the dump is to take.

## Tier 0 — free / configuration wins

- **Encrypt file *contents*, not just the index.** Set a broad
  `encryption_include_filters`, e.g.
  `*.gd,*.gdc,*.tscn,*.scn,*.res,*.tres,*.json,*.cfg,*.csv,*.gdshader`.
  Empty filters (or filters without the leading `*`) = directory-only encryption
  = content-carvable. Leave bulk art (`*.png`, `*.ogg`) unencrypted for load
  performance — it's low-value to hide. (See
  [`common-misconfigurations.md`](common-misconfigurations.md) for the exact ways
  this is set wrong.)
- **Verify it actually took**: the exported pack should grow (each encrypted file
  gains a ~40-byte header + padding), and valid `GDSC` scripts in the body should
  drop to 0. If the size doesn't change, encryption isn't really on. Use
  [`verifying-encryption.md`](verifying-encryption.md) and `check_encryption.py`.
- **Rotate a leaked key.** If a key has ever shipped in a cracked build, treat it
  as public: generate a new one (`openssl rand -hex 32`), rebuild templates, re-export.
- **Move genuine secrets server-side.** Anti-cheat, economy/drop rules,
  validation — anything truly sensitive shouldn't ship in the client at all. The
  only unconditional protection.

## Tier 1 — engine changes that defeat the dump-and-scan

You already build custom export templates (required for PCK encryption), so you
can modify the engine.

### Split-key + reconstruct-on-use + secure-wipe (link B)

Never store the key as 32 contiguous bytes. Store it as XOR shares, and at the
point of use XOR them into a short-lived buffer, decrypt, then **zero the buffer
immediately**. Reconstruct **per decrypt call** — do not cache the assembled key.

Offline, generate shares (`key = a ^ b ^ c`; any 1–2 shares reveal nothing):

```python
import secrets
key = bytes.fromhex("...")                       # your 32-byte key
a = secrets.token_bytes(32); b = secrets.token_bytes(32)
c = bytes(k ^ x ^ y for k, x, y in zip(key, a, b))
assert bytes(x ^ y ^ z for x, y, z in zip(a, b, c)) == key
```

Reconstruct/use/wipe in native code:

```cpp
static void secure_zero(void *p, size_t n) {
#if defined(_WIN32)
    SecureZeroMemory(p, n);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p; while (n--) *vp++ = 0;
#endif
}

template <typename Fn> static auto with_key(Fn &&use) {
    unsigned char key[32];
#if defined(_WIN32)
    VirtualLock(key, sizeof key);                // keep off the pagefile while live
#endif
    for (int i = 0; i < 32; ++i)
        key[i] = KEY_SHARE_A[i] ^ KEY_SHARE_B[i] ^ KEY_SHARE_C[i];
    auto r = use(key, sizeof key);               // decrypt happens here, synchronously
    secure_zero(key, sizeof key);                // wipe before returning
#if defined(_WIN32)
    VirtualUnlock(key, sizeof key);
#endif
    return r;
}
```

This shrinks the key's lifetime in RAM from "the whole session" to "microseconds,
N times" — which a blind dump almost certainly misses. Enhancements: keep the
shares in separate translation units; derive one share at runtime (e.g. from a
checksum of a code region) so it isn't a plain static array.

### White-box AES (strongest vs memory dump)

Replace the AES used for the PCK with a white-box implementation: the key is baked
into lookup tables so a discrete 32-byte key **never exists in memory at all**.
Expensive to implement and academically breakable (DCA/DFA), but it moves the
attacker from a 60-second script to implementing a white-box cryptanalysis attack.

### Custom container (link C)

The static brute force relies on the stored `md5(plaintext directory)` as a
verification oracle. A custom pack format without a known-plaintext checksum
removes offline verification. (Note: a popular RE tool already supports a
`--custom-decryption-script` hook, so merely re-parameterizing stock AES isn't
enough — the scheme itself must differ.)

## Tier 2 — binary-level (link A)

- **Commercial protectors** (VMProtect / Themida / Enigma) add anti-debug,
  anti-dump, import obfuscation, and code virtualization in one step. The standard
  choice for shipped games; defeats casual/automated dumping.
- **Roll-your-own anti-tamper**: anti-debug checks (`IsDebuggerPresent`, PEB
  flags, timing), deny handle opens / hook `MiniDumpWriteDump`, run at higher
  integrity, and `CryptProtectMemory` the key between uses.
- **Native code for the crown jewels**: GDScript `.gdc` decompiles cleanly back
  to readable `.gd`. Compiled C++ (GDExtension) has no equivalent decompiler —
  move the most sensitive client logic there, ideally virtualized.

## On GDScript obfuscators

Source-level GDScript obfuscators (e.g. GDMaim) can mangle identifiers at export,
but they are **export-pipeline- and engine-version-sensitive**: they require the
right `script_export_mode` so the obfuscator receives raw `.gd`, and abandoned/
outdated addons may simply fail to load on current Godot. Treat obfuscation as a
readability speed-bump on top of encryption, not a substitute — and verify on the
*exported* build that identifiers are actually mangled (see
[`common-misconfigurations.md`](common-misconfigurations.md) §8).

## Recommended roadmap

| Tier | Action | Effort | Stops automated dump-and-scan? |
|---|---|---|---|
| 0 | Encrypt file contents (filters) | minutes | No (closes static carving) |
| 0 | Move secrets server-side | design | N/A — makes the rip pointless |
| 1 | Split-key + wipe (native) | days | **Yes** — no contiguous key to find |
| 1 | Commercial packer / anti-dump | days | **Yes** — blocks the dump itself |
| 2 | GDExtension for sensitive logic | weeks | Hardens what survives |
| 3 | White-box AES + custom container | weeks+ | **Yes** — nothing to extract, no oracle |

**Minimum to defeat the automated attack:** Tier 0 + **either** split-key/wipe
**or** a packer. Doing both is belt-and-suspenders.

For a condensed, actionable version of all of the above, see
[`defenders-checklist.md`](defenders-checklist.md). For *why* the memory-dump
route works regardless of key rotation, see
[`memory-key-recovery.md`](memory-key-recovery.md).

## What NOT to rely on

- Renaming/hiding the PCK section — carving is signature-based.
- Index-only encryption — contents are still carvable.
- A baked key without memory protection — recoverable from a dump in seconds.
- Stock AES with a thin custom wrapper — anticipated by existing tooling.

The throughline: assume the attacker can run the client and read its memory.
Design so that what they can read is either useless (server-authoritative, native,
obfuscated) or doesn't contain the key in usable form (white-box / split-key / wiped).
