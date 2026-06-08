"""
frida_keycatch.py — recover the Godot PCK key by HOOKING the AES key-setup
routine at runtime, defeating "wipe the key after use" hardening.

A build that securely wipes the reconstructed key defeats a blind memory dump
(the key is gone microseconds after use). But the key must still be *handed to
the AES routine* to be used — so instrumenting that call captures it regardless
of how briefly it lives. This is the rung above the memory dump: it needs real
RE (locate the unexported AES setkey function in a stripped static binary) plus
dynamic instrumentation, but it works.

How it works:
  1. Fingerprint the mbedtls AES-NI key-setup code by scanning for the
     `aeskeygenassist` instruction cluster (66 0F 3A DF).
  2. Derive candidate function entries near the cluster and map file offsets to
     runtime RVAs via the PE section table.
  3. Frida-hook those entries; on each call read the key pointer argument
     (2nd arg = rdx, plus rcx as a fallback) and verify the 32 bytes against the
     encrypted directory's MD5 oracle.

Requires: pip install frida   (Windows x64 target using AES-NI).

Usage:
  python frida_keycatch.py <game.exe> [--seconds 30]

Authorized use only — your own builds or work you're permitted to analyze.
"""
import sys
import os
import re
import time
import struct
import argparse

import godot_pck_common as g


def pe_sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    st = pe + 24 + opt
    out = []
    for i in range(nsec):
        s = data[st + i * 40: st + i * 40 + 40]
        va, rs, rp = struct.unpack_from("<I", s, 12)[0], struct.unpack_from("<I", s, 16)[0], struct.unpack_from("<I", s, 20)[0]
        out.append((va, rs, rp))
    return out


def find_setkey_entries(data):
    """Candidate AES-setkey function entry RVAs, found via the aeskeygenassist cluster."""
    secs = pe_sections(data)

    def f2rva(fo):
        for va, rs, rp in secs:
            if rp <= fo < rp + rs:
                return va + (fo - rp)
        return None

    cluster = [m.start() for m in re.finditer(rb"\x66\x0f\x3a\xdf", data)]
    if not cluster:
        return []
    lo, hi = max(min(cluster) - 1024, 1), max(cluster) + 256

    # An entry is a code byte right after 0xCC alignment padding that looks like a
    # function prologue or an immediate load of the key argument ([rdx]/[rcx]).
    def looks_like_entry(b):
        return (b[0:3] == b"\x48\x83\xec"      # sub rsp, imm8
                or b[0:2] == b"\x48\x89"        # mov [rsp+x], reg  (reg-save prologue)
                or b[0] == 0x55                 # push rbp
                or b[0:3] == b"\x0f\x10\x02"    # movups xmm0, [rdx]
                or b[0:3] == b"\x0f\x10\x0a"    # movups xmm1, [rdx]
                or b[0:4] == b"\xf3\x0f\x6f\x02")  # movdqu xmm0, [rdx]

    rvas = []
    for i in range(lo, hi):
        if data[i - 1] == 0xCC and data[i] != 0xCC and looks_like_entry(data[i:i + 6]):
            rva = f2rva(i)
            if rva:
                rvas.append(rva)
    return sorted(set(rvas))


JS_TEMPLATE = """
var base = Process.getModuleByName(%(mod)r).base;
var rvas = %(rvas)s;
rvas.forEach(function(rva){
  try {
    Interceptor.attach(base.add(rva), {
      onEnter: function(){
        function hx(p){ try { var b=new Uint8Array(p.readByteArray(32)); var s='';
          for(var i=0;i<32;i++){ s+=('0'+b[i].toString(16)).slice(-2); } return s; } catch(e){ return null; } }
        send({ rva: rva, rcx: hx(this.context.rcx), rdx: hx(this.context.rdx) });
      }
    });
  } catch(e){ send({err: ''+e, rva: rva}); }
});
send({ready:true});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--seconds", type=int, default=30)
    args = ap.parse_args()

    import frida  # imported here so the file is importable without frida installed

    data = open(args.exe, "rb").read()
    hdr = g.parse_pck_header(data, g.find_embedded_pck_start(data))
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])

    rvas = find_setkey_entries(data)
    if not rvas:
        raise SystemExit("No aeskeygenassist cluster found — target may not use AES-NI.")
    print("Hooking %d candidate AES-setkey entries: %s"
          % (len(rvas), ", ".join("0x%x" % r for r in rvas)))

    js = JS_TEMPLATE % {"mod": os.path.basename(args.exe), "rvas": str(rvas)}
    found, seen = {}, set()

    def on_message(msg, _data):
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        if p.get("ready"):
            print("[*] hooks installed"); return
        if p.get("err"):
            return
        for reg in ("rdx", "rcx"):
            h = p.get(reg)
            if not h or h in seen:
                continue
            seen.add(h)
            try:
                key = bytes.fromhex(h)
            except ValueError:
                continue
            if g.verify_key(key, fae) is not None:
                print("\n[+++] KEY CAUGHT via hook @0x%x (%s): %s" % (p["rva"], reg, key.hex()))
                found["key"] = key.hex()

    dev = frida.get_local_device()
    pid = dev.spawn([args.exe])
    sess = dev.attach(pid)
    scr = sess.create_script(js)
    scr.on("message", on_message)
    scr.load()
    dev.resume(pid)
    print("[*] spawned pid %d; capturing during startup..." % pid)
    t = time.time()
    while time.time() - t < args.seconds and "key" not in found:
        time.sleep(0.5)
    try:
        dev.kill(pid)
    except Exception:
        pass
    if "key" in found:
        print("\nRECOVERED KEY (hex): " + found["key"])
    else:
        print("\nNo key caught — try widening --seconds or revisiting the entry heuristics.")


if __name__ == "__main__":
    main()
