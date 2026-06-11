"""
find_aes_rvas.py — statically locate the mbedtls **AES-NI key-setup** function
entries inside a Godot (x64 Windows) PE, by scanning for the `aeskeygenassist`
instruction cluster and resolving the enclosing function entries to runtime RVAs.

Why you'd use this:
  * As a fast, no-spawn diagnostic before running `frida_keycatch.py` — confirm the
    target actually *has* an AES-NI key-setup cluster and see which addresses the
    hook will target.
  * To feed addresses to a debugger / your own instrumentation.
  * To sanity-check a build: **zero candidates means the binary doesn't use the
    AES-NI key schedule** (it may use mbedtls's *software* AES path, or a custom
    key-setup). In that case `aeskeygenassist` won't fingerprint the right routine
    and a runtime hook on these entries will catch nothing — see
    docs/frida-key-hooking.md ("When it finds nothing").

`frida_keycatch.py` imports `find_setkey_entries()` from this module, so the two
always agree on how entries are located.

Usage:
  python find_aes_rvas.py <game.exe> [--loose]

Authorized use only — your own builds or work you're permitted to analyze.
"""
import sys
import re
import struct
import argparse

AESKEYGENASSIST = rb"\x66\x0f\x3a\xdf"  # aeskeygenassist xmm, xmm/m128, imm8


def pe_sections(data):
    """[(virtual_addr, raw_size, raw_ptr)] for every PE section."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    st = pe + 24 + opt
    out = []
    for i in range(nsec):
        s = data[st + i * 40: st + i * 40 + 40]
        va = struct.unpack_from("<I", s, 12)[0]
        rs = struct.unpack_from("<I", s, 16)[0]
        rp = struct.unpack_from("<I", s, 20)[0]
        out.append((va, rs, rp))
    return out


def _file_to_rva(secs, fo):
    for va, rs, rp in secs:
        if rp <= fo < rp + rs:
            return va + (fo - rp)
    return None


def _looks_like_entry(b):
    """True if `b` (a few bytes) looks like an MSVC function prologue or an
    immediate load of the AES key argument ([rdx]/[rcx])."""
    return (b[0:3] == b"\x48\x83\xec"          # sub rsp, imm8
            or b[0:2] == b"\x48\x89"           # mov [rsp+x], reg  (reg-save prologue)
            or b[0] == 0x55                    # push rbp
            or b[0:3] == b"\x0f\x10\x02"       # movups xmm0, [rdx]
            or b[0:3] == b"\x0f\x10\x0a"       # movups xmm1, [rdx]
            or b[0:4] == b"\xf3\x0f\x6f\x02")  # movdqu xmm0, [rdx]


def find_setkey_entries(data, loose=False):
    """Candidate AES-setkey function entry RVAs near the aeskeygenassist cluster.

    Default (precise): a code byte right after 0xCC padding that looks like a
    function prologue / key-argument load. `loose=True` widens the net to every
    16-byte-aligned address preceded by 0xCC padding (higher recall, more false
    positives — harmless because the catcher verifies each candidate)."""
    secs = pe_sections(data)
    cluster = [m.start() for m in re.finditer(AESKEYGENASSIST, data)]
    if not cluster:
        return []
    lo, hi = max(min(cluster) - 0x1400, 1), max(cluster) + 0x100

    rvas = []
    for i in range(lo, hi):
        if data[i - 1] != 0xCC or data[i] == 0xCC:
            continue
        rva = _file_to_rva(secs, i)
        if rva is None:
            continue
        if loose:
            if rva % 16 == 0:
                rvas.append(rva)
        elif _looks_like_entry(data[i:i + 6]):
            rvas.append(rva)
    return sorted(set(rvas))


def count_occurrences(data):
    return len(re.findall(AESKEYGENASSIST, data))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("exe")
    ap.add_argument("--loose", action="store_true",
                    help="high-recall mode: every aligned entry after 0xCC padding")
    args = ap.parse_args()

    data = open(args.exe, "rb").read()
    occ = count_occurrences(data)
    rvas = find_setkey_entries(data, loose=args.loose)

    print("aeskeygenassist occurrences : %d" % occ)
    print("candidate setkey entries    : %d%s" % (len(rvas), "  (loose)" if args.loose else ""))
    for r in rvas:
        print("  0x%x" % r)
    if occ and not rvas and not args.loose:
        print("\n(no entries matched the precise heuristic — try --loose)")
    if not occ:
        print("\nNo aeskeygenassist found: this build does not use the mbedtls AES-NI")
        print("key schedule. A runtime hook on AES-NI setkey will catch nothing here")
        print("(software AES / custom key-setup). See docs/frida-key-hooking.md.")
    if rvas:
        print("\nRVAS = [%s]" % ", ".join("0x%x" % r for r in rvas))


if __name__ == "__main__":
    main()
