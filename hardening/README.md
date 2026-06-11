# Hardening reference: stop the PCK key being recoverable from memory

Reference patches and notes for closing the **memory-dump key-recovery** route
(see [`../docs/memory-key-recovery.md`](../docs/memory-key-recovery.md)). These
target **Godot `4.6.1-stable`** and require **custom export templates** (you're
already building those if you use PCK encryption).

> Defensive use on your own builds. These are reference examples — read them,
> understand them, and **verify the result with the toolkit** before trusting it.

## The problem, precisely

A stock encrypted Godot build leaves the AES key recoverable from RAM for three
reasons:

1. **The raw key is a resident global.** The build generates
   `script_encryption_key.gen.cpp` containing a literal
   `uint8_t script_encryption_key[32] = { ...raw bytes... };`. That global lives
   in `.data` for the whole process — and is even visible on disk.
2. **The working copy isn't wiped.** `file_access_pack.cpp` copies the key into a
   `Vector`, passes it to `FileAccessEncrypted`, and lets it go out of scope.
   Godot's `Vector` frees **without zeroing**, so the bytes linger in freed heap.
3. **`FileAccessEncrypted` keeps its own copy.** `open_and_parse` does
   `key = p_key` and never zeroes that member — another resident/lingering copy.

Our scanner finds *any* of these. So a fix must address **all** of them.

## Three layers

### Layer 1 — secure-wipe the working copies  (patch, drop-in)

[`patches/0001-secure-wipe-pck-key.patch`](patches/0001-secure-wipe-pck-key.patch)
adds a non-optimizable `secure_zero` and wipes:

- `FileAccessEncrypted::key` right after the AES schedule is built, and again as a
  backstop in `_close()` (covers write mode), and
- the reconstructed key `Vector` in `file_access_pack.cpp` immediately after each
  `open_and_parse` (both the directory and per-file sites).

This eliminates problems **#2 and #3**. Applies cleanly to pristine 4.6.1-stable:

```bash
cd /path/to/godot          # a clean 4.6.1-stable checkout
git apply --check hardening/patches/0001-secure-wipe-pck-key.patch
git apply        hardening/patches/0001-secure-wipe-pck-key.patch
```

### Layer 2 — split-key storage  (removes the resident raw global)

Layer 1 still leaves problem **#1**: the raw key global. Layer 2 replaces it with
**XOR shares** reconstructed on demand, so no single 32-byte key exists at rest.
This is build-entangled (it changes how the key is compiled in), so it's
documented as a recipe rather than a one-file patch — see
[`split-key-storage.md`](split-key-storage.md). Use [`split_key.py`](split_key.py)
to generate the shares header.

> Note: a developer who has already "split the key into 3 variables" has done
> Layer 2 their own way — but **Layer 1 is what they're usually missing**, and
> without it the *assembled* key still lingers in memory.

### Layer 3 — server-held key share  (kills offline reconstruction + offline hooking)

Layers 1–2 are entirely client-side: they raise the cost of lifting the key from a
running or dumped process, but the shares still ship inside the binary — so a
determined attacker can reconstruct the key **offline**, or run offline and hook it.
Layer 3 keeps **one XOR share on your server** and releases it only after the client
connects, so the binary alone holds `key ^ S` (useless) and any extraction is forced
into a live, logged, **revocable** session.

Full reference implementation — engine-source changes *and* a Python server, for
Godot 4.6.1 — is in [`server-key-share.md`](server-key-share.md).

## Verify it actually worked

The toolkit is the test. After rebuilding the template and re-exporting:

```bash
# Windows: launch + dump, then scan (falls through to exhaustive align-1)
powershell -File tools/dump_game_memory.ps1 -Exe game.exe -Out game.dmp
python tools/extract_key_from_dump.py game.exe game.dmp --align 8
```

- **No hit at align-1** → the resident-key hole is closed against this attack.
- **Still a hit** → a copy survived; the reported dump offset shows where to look.

## Honest limits — this wipe does NOT stop runtime hooking

The wipe defeats the **blind, automated dump-and-scan**. It does **not** stop an
attacker who instruments the live process: the key must still be handed to the AES
routine, so hooking that call captures it at the moment of use — **demonstrated**,
the key falls out in seconds even on a fully wiped build. See
[`../docs/post-wipe-attack-surface.md`](../docs/post-wipe-attack-surface.md) for
the working technique (`tools/frida_keycatch.py`), Time-Travel Debugging, and
**offline reconstruction from the shares** (which needs no runtime at all).

- The decisive next step is therefore **not more client-side wiping** but a
  **server-held key share** (Layer 3 above — full reference in
  [`server-key-share.md`](server-key-share.md)): keep one of the XOR shares on your
  authenticated server and fetch it per session. That makes offline reconstruction
  impossible and forces any hook into a live, revocable session. (Pair with
  anti-debug / virtualization to raise the hooking cost.)
- Eliminating even the transient hooked copy needs **white-box AES** (the key
  never exists as discrete bytes) — see [`../docs/hardening.md`](../docs/hardening.md).
- Client-side protection is never absolute (the analog hole). The goal is to make
  the automated, turnkey attack fail and force expensive, per-session manual RE.
