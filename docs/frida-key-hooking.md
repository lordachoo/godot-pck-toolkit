# Runtime key hooking with Frida

This is the rung **above** a memory dump. A build can securely wipe the
reconstructed PCK key microseconds after it's used — defeating a blind
[`extract_key_from_dump.py`](memory-key-recovery.md). But the key still has to be
*handed to the AES routine* to decrypt anything, so if you instrument that call you
capture the key at the instant of use, no matter how briefly it lives in memory.

Two tools cover this:

| Tool | Job |
|---|---|
| [`tools/find_aes_rvas.py`](../tools/find_aes_rvas.py) | **Static**: locate the mbedtls AES-NI key-setup function entries in the PE. No spawn. |
| [`tools/frida_keycatch.py`](../tools/frida_keycatch.py) | **Dynamic**: spawn the game, hook those entries, verify each captured 32-byte value against the directory's MD5 oracle. |

> ⚠️ Authorized use only — your own builds or work you're permitted to analyze.
> Requires `pip install frida`, a Windows x64 target, and (for the default path) a
> build that uses AES-NI.

## How it works

1. **Fingerprint.** mbedtls's AES-NI key schedule uses the `aeskeygenassist`
   instruction (`66 0F 3A DF`). It appears in a tight cluster inside the setkey
   routines. We scan the executable for it.
2. **Resolve entries.** From the cluster we walk back to function entries (a code
   byte right after `0xCC` int3 padding that looks like an MSVC prologue or a load
   of the key argument), and map each file offset to a runtime RVA via the PE
   section table.
3. **Hook + verify.** Frida attaches to each entry. The setkey signature is
   `(ctx, key, keybits)`, so the key pointer is in `rdx` (with `rcx`/`r8` as
   fallbacks). On every call we read 32 bytes and test them with the **MD5 oracle**
   — decrypt the encrypted directory and compare the MD5. A match is the real key;
   everything else is ignored. No guessing, no false positives.

## Step 0 — locate the entries (static, fast)

Run this first as a no-spawn sanity check and to see what the hook will target:

```console
$ python find_aes_rvas.py game.exe
aeskeygenassist occurrences : 32
candidate setkey entries    : 8
  0xa8a390
  0xa8a450
  0xa8a5a0
  0xa8a610
  0xa8a8f0
  0xa8ab00
  0xa8adc0
  0xa8b0c0

RVAS = [0xa8a390, 0xa8a450, 0xa8a5a0, 0xa8a610, 0xa8a8f0, 0xa8ab00, 0xa8adc0, 0xa8b0c0]
```

If the precise heuristic returns nothing but occurrences is non-zero, widen it:

```console
$ python find_aes_rvas.py game.exe --loose
aeskeygenassist occurrences : 32
candidate setkey entries    : 12  (loose)
...
```

## Step 1 — catch the key (dynamic)

`frida_keycatch.py` reads the verification oracle from a **separate `.pck`** if one
sits next to the exe (the common case for non-embedded exports), otherwise from a
PCK **embedded** in the exe. It auto-locates the RVAs (or pass your own).

```console
$ python frida_keycatch.py game.exe
[*] oracle: separate pck: game.pck (file_count=40270)
[*] hooking 8 candidate AES-setkey entries: 0xa8a390, 0xa8a450, 0xa8a5a0, 0xa8a610, 0xa8a8f0, 0xa8ab00, 0xa8adc0, 0xa8b0c0
[*] 8 hooks installed; capturing...
[*] spawned pid 24576; capturing for 30s...

[+++] KEY CAUGHT via hook @0xa8adc0 (rdx): 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

RECOVERED KEY (hex): 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Useful flags / forms:

```bash
python frida_keycatch.py game.exe game.pck      # explicit separate pck
python frida_keycatch.py game.exe --seconds 60  # slow startups
python frida_keycatch.py game.exe --loose       # widen the auto RVA search
python frida_keycatch.py game.exe --rva 0xa8adc0 --rva 0xa8ab00   # hook specific entries
```

Feed the recovered key straight into extraction:

```bash
python frida_keycatch.py game.exe | tee key.txt
python extract_godot_project.py game.exe --key <hex-from-above> --out ../out/project
```

## When it finds nothing

A null result is **not** proof the key is safe — it usually means the hook was on
the wrong routine or the key never got used in the window. Diagnose in this order:

```console
$ python frida_keycatch.py game.exe
[*] oracle: separate pck: game.pck (file_count=40270)
[*] hooking 8 candidate AES-setkey entries: ...
[*] 8 hooks installed; capturing...
[*] spawned pid 31840; capturing for 30s...

No key caught. Possible reasons:
  * the build uses software/custom AES (no AES-NI setkey) — these hooks
    are on the wrong routine; ...
```

1. **Software or custom AES key-setup (most important).** `aeskeygenassist` only
   appears on the **AES-NI** path. If the build forces mbedtls's *software* key
   schedule, or wraps setkey in a custom routine (e.g. a split/obfuscated key
   expansion), the cluster you found belongs to AES-NI code that the PCK key never
   touches — so the hook fires zero useful times even though the game clearly
   decrypted its pack. `find_aes_rvas.py` reporting *zero* occurrences is the clear
   tell; if it reports a cluster but the catch is empty while the game fully booted,
   suspect a software/custom path and hook **that** routine instead (locate it via
   the call into `FileAccessEncrypted` / `CryptoCore::AESContext::set_encode_key`).
2. **The pack was never decrypted in the window.** If the target failed to start —
   e.g. it requires a **server-held key share** that wasn't available (offline), or
   it crashed early — no key is ever assembled. That's a *defense working*, not a
   tooling failure. Increase `--seconds` only if startup is genuinely slow.
3. **The entry heuristic missed it.** Try `--loose`, or pass `--rva` with addresses
   from your own disassembly.

## Why this matters (and what actually stops it)

Hooking shows that **wiping the key after use does not protect it** — the value is
recoverable at the moment of use. So the wipe/secure-erase hardening in
[`hardening.md`](hardening.md) raises the bar (kills blind dumps) but does not close
this rung. What genuinely raises it further:

- **Software / white-box AES** — no clean `(ctx, key)` entry to hook; the key is
  diffused into the round-key schedule. Large effort, partial.
- **A server-held key share** released only after the client authenticates — the
  binary alone holds `key ^ S` (garbage), so **offline** reconstruction *and*
  run-offline-then-hook both die, and any online extraction is gated, logged, and
  revocable. It does **not** stop a logged-in attacker hooking their own live
  session (the key must still enter memory to decrypt). See
  [`post-wipe-attack-surface.md`](post-wipe-attack-surface.md).
- **Anti-debug / anti-instrumentation** — detect Frida/attach; raises effort, never
  absolute.

The honest summary: against an authenticated, online attacker the in-memory key is
always ultimately reachable. The defenses above turn "trivial and offline for
anyone" into "online-only, gated, attributable, and revocable."
