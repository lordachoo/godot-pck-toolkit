# Recovering the PCK key from a memory dump

When the encryption key cannot be found statically in the executable (common —
it's often assembled at runtime, not stored as 32 contiguous bytes on disk), it
can still be recovered from a dump of the running process. This is the
**format- and obfuscation-agnostic** route: the client must hold the cleartext
key in RAM to mount its PCK, so it's always there at runtime.

> Authorized use only — your own builds or work you're permitted to analyze.

## Why it always works (the "oracle")

You don't need to know the key in advance. The encrypted directory stores an
**MD5 of the correct decrypted directory** — the build's own self-check. That
lets you test any 32-byte candidate instantly:

- decrypt the directory with the candidate → compute MD5 → compare to the stored MD5
- wrong guess → garbage → mismatch; right guess → exact match

So the build itself confirms when a guess is correct. The key is somewhere in the
~GBs of RAM; you slide a 32-byte window across the dump and run the test until it
matches (hundreds of millions of candidates in seconds across many cores).

**Rotating the key does not help.** You're never searching for a specific known
value — you're searching for "the 32 bytes that correctly open *this* build,"
and every build ships the self-check that recognizes success. (Removing the MD5
self-check doesn't save it either: the key is still resident, and a decrypted
directory is recognizable other ways — e.g. every path starts with `res://`.)

## Procedure

```bash
# 1) Dump the running game's full memory (Windows; no admin needed, same-user)
powershell -File dump_game_memory.ps1 -Exe C:\path\to\game.exe -Out C:\path\to\game.dmp

# 2) Scan the dump for the key (uses the exe's directory MD5 as the oracle)
python extract_key_from_dump.py C:\path\to\game.exe C:\path\to\game.dmp --out key.bin
```

The dump helper launches the game, waits a few seconds for the engine to mount
the PCK (this happens at startup, before the main scene / before networking),
writes a full-memory minidump via `MiniDumpWriteDump`, then kills the process.

## Alignment — why the scanner tries 8, then 1

This is the part that trips people up, so the tool documents and automates it:

1. **Minidump file offsets ≠ RAM addresses.** A dump wraps each memory region in
   a container, so a byte that was 16-aligned in RAM lands at an arbitrary offset
   in the `.dmp` file. A naive "scan every 16th file offset" therefore **misses
   the key**. The scanner instead parses the dump's memory map
   (`Memory64List` / `MemoryList`) and scans each region at its **true
   virtual-address alignment**.

2. **The key is usually 8-aligned, not 16.** The key lives in a Godot
   `Vector`/`CowData` allocation. Godot's allocator prepends a size header before
   the data, so the returned data pointer is commonly **8-byte aligned**, and the
   exact alignment **varies between runs / heap layouts**. In practice the key
   has been observed at both 16- and 8-aligned addresses.

3. **So:**
   - **`--align 8` (default)** covers both 8- and 16-aligned keys, ~2× the work
     of align-16 but reliable. (Align-16 is faster but can — and does — miss.)
   - If align-8 misses, the tool **falls back to align-1** (exhaustive: scans
     every byte offset). Slower, but it will find the key if it's there at all.
   - You can force a value with `--align`.

Rule of thumb: **start at 8; if nothing, let it fall through to 1.** Only use 16
when you want a fast first pass and are willing to retry.

## Performance notes

- Scanning is parallelized across CPU cores. On Windows a process pool is capped
  at 60 workers (the OS limits `WaitForMultipleObjects` to 63 handles).
- A cheap per-candidate filter (decrypt only the first CFB block and sanity-check
  the first directory entry's `path_len`) avoids a full directory decrypt on the
  ~all-but-one candidates that aren't the key.
- The dump is memory-mapped read-only and shared across workers.
- A boundary guard skips windows that would run past the end of a region/file
  (otherwise a short read at the tail yields a 0-byte "key" and crashes AES).

## What stops this

Nothing client-side stops it absolutely (the analog hole), but you can make the
"slide a window and test" approach find nothing:

- **Don't keep the key resident as 32 contiguous bytes** — split it into shares
  and reconstruct into a transient buffer only at the moment of use, then
  secure-wipe it. See [`hardening.md`](hardening.md).
- **White-box AES** — the key never exists as discrete bytes in memory at all.

Both require engine-level (custom export template) changes, not export settings.
See [`../hardening/`](../hardening/) for ready-to-apply 4.6.1-stable reference
patches (secure-wipe + split-key storage) and how to verify them with this tool.
