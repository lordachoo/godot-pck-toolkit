# Post-wipe attack surface (the rung above the memory dump)

> Authorized/defensive use only. This documents a *working* attack against a build
> that has **already applied the secure-wipe hardening** — i.e. the rung above a
> blind memory dump. The headline mitigation (a **server-held key share** — full
> reference implementation in
> [`../hardening/server-key-share.md`](../hardening/server-key-share.md); see
> "Counters") is the recommended next step and may still be in progress for a
> given project.

Once a build securely wipes the reconstructed key (so a **blind memory dump**
finds nothing — confirmed by an exhaustive byte-aligned scan), the attacker moves
to techniques that don't rely on the key sitting around. This is the hard ceiling
of client-side protection: **the key must still be handed to the cipher to be
used, so anyone who can observe that moment gets it.**

## What survives the wipe

### 1. Runtime hooking (the practical one) — DEMONSTRATED

Hook the function that receives the key and read it at the instant of use. The
wipe is irrelevant: you intercept *during* use, not after.

On a stripped, statically-linked Godot release exe there are no symbols, so the
work is **locating** the unexported AES key-setup routine. It's findable:

1. Godot statically links mbedtls; on a modern CPU it uses **AES-NI**, whose
   key expansion emits the `aeskeygenassist` instruction (`66 0F 3A DF`).
   Scanning the binary for that opcode pinpoints the key-setup code cluster.
2. Walk back from the cluster to the enclosing function entries (code right after
   `0xCC` alignment padding, starting with a prologue or an immediate `[rdx]`
   load), and map file offsets → runtime RVAs via the PE section table.
3. Frida-hook those entries; on entry the key pointer is the 2nd argument
   (`rdx` on Win64). Read 32 bytes and verify against the directory MD5 oracle.

**Result (observed):** against a build with the wipe applied — where an exhaustive
`align-1` memory-dump scan found **nothing** — this hook captured the key in a few
seconds:

```
[+++] KEY CAUGHT via hook @0x.... (rdx): <32-byte key, oracle-verified>
```

Tooling: `tools/frida_keycatch.py` (generalized — fingerprints the cluster, hooks
the candidate entries, oracle-verifies). Requires `pip install frida`.

Effort delta vs. the dump: the blind dump is a one-line tool with zero RE; this
needs instruction-pattern fingerprinting + dynamic instrumentation. That's the
skill bar the wipe successfully raises — but a competent RE clears it.

Variants: a debugger breakpoint on the same address, `Detours`/`EasyHook`/API
Monitor, or a DLL injected before startup achieve the same thing.

### 2. Time-Travel Debugging (you can't out-wipe a recording)

WinDbg **TTD** records the entire execution. A key that lived for microseconds is
in the trace forever; you replay to the AES setkey call (same address-finding as
above) and read it, deterministically, offline. Defeats wipe *and* timing-based
luck.

### 3. Offline reconstruction from the shares (no runtime at all)

Split-key storage is **obfuscation, not cryptography**: the share arrays *and* the
XOR-combine logic both ship in the binary. A reverse engineer who locates them
computes `A ^ B ^ C` on their desk — never runs the game, never needs a dump or a
hook. This is arguably the *cheapest* path for a determined attacker, and the
worst for you because it's "crack once, publish the key forever."

### 4. AES key-schedule recovery

Even with the raw 32-byte key wiped, the expanded **key schedule** (240 bytes for
AES-256) exists in the cipher context during decryption, and is mathematically
**invertible back to the key**. If that context isn't also short-lived/zeroed, a
dump timed to a decrypt — or a schedule-aware scan — recovers the key from it.

## Counters, ranked by what they actually buy

| Counter | Neutralizes | Reality |
|---|---|---|
| **Server-derived key share** (fetch one share per session from your authenticated server) | **#3 offline reconstruction** outright; makes **#1/#2** require a *live, authenticated, revocable* session | **The decisive move.** The offline binary can't rebuild the key; every extraction needs a real account you can rate-limit, fingerprint, and ban. Converts "crack once → share" into "need a live session each time." For a client that already talks to a server, it's natural. See [`../hardening/server-key-share.md`](../hardening/server-key-share.md) for a full reference implementation. |
| **Code virtualization** (VMProtect / Themida) on the reconstruct + AES path | Raises the cost of **#1/#2** (hide/obfuscate the call so it can't be found or hooked easily) | Strongest *practical* anti-instrumentation. Beatable by experts, not by scripts. |
| **Anti-debug / anti-inject / anti-Frida / anti-TTD** | Casual **#1/#2** | Cat-and-mouse; each check is individually bypassable. Detect HW breakpoints, known Frida/injection artifacts, timing anomalies; bail on detection. |
| **White-box AES** | Removes the **#1** target (no discrete key exists even at use) | Big effort; breakable by white-box cryptanalysis (DCA/DFA) — specialist work. |
| **Short-lived/zeroed cipher context** | **#4** | Keep the AES context local-scope and wiped; cheap, do it. |
| **Server-authoritative logic** | Everything that matters | The only unconditional fix — for logic/data you can keep off the client entirely. |

## The honest ceiling

No client-side scheme stops an attacker who can run the client and instrument it —
the cipher must see the key. So the realistic goal isn't "unbreakable," it's:

1. **Defeat automated/casual attacks** — *done* by encryption + wipe (rungs 1–3
   of the recovery ladder).
2. **Force expensive, skilled, per-session RE** for anything beyond that — done by
   **server-derived shares + virtualization**, which also give you detection and
   revocation you don't have today.

The wipe was the right last *client-only* step. The next meaningful gain is
**architectural** (move a share, and ideally the real secrets, to the server),
not more client-side hiding.
