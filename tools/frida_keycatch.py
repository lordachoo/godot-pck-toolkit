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
     `aeskeygenassist` instruction cluster (66 0F 3A DF)  [find_aes_rvas.py].
  2. Derive candidate function entries near the cluster and map file offsets to
     runtime RVAs via the PE section table.
  3. Frida-hook those entries; on each call read the key-pointer argument
     (rdx / rcx / r8) and verify the 32 bytes against the encrypted directory's
     MD5 oracle.

Works on **embedded** PCKs (inside the .exe) and **separate** `.pck` files: the
oracle is read from a sibling/explicit `.pck` if present, else from the embedded
pack. See docs/frida-key-hooking.md for a walk-through and example output.

Requires: pip install frida   (Windows x64 target using AES-NI).

Usage:
  python frida_keycatch.py <game.exe> [game.pck] [--seconds 30]
                                       [--rva 0x.. --rva 0x..] [--loose]

Authorized use only — your own builds or work you're permitted to analyze.
"""
import os
import time
import argparse

import godot_pck_common as g
from find_aes_rvas import find_setkey_entries


def load_oracle(exe, pck):
    """Return (fae_header, source_str): the encrypted-directory MD5 oracle used to
    verify captured keys. Prefer an explicit/sibling .pck (separate export), else
    fall back to a PCK embedded in the exe."""
    if pck and os.path.exists(pck):
        data = open(pck, "rb").read()
        if data[:4] == g.PACK_MAGIC:
            hdr = g.parse_pck_header(data, 0)
            return g.read_dir_fae_header(data, hdr["dir_offset"]), "separate pck: " + pck
    data = open(exe, "rb").read()
    hdr = g.parse_pck_header(data, g.find_embedded_pck_start(data))
    return g.read_dir_fae_header(data, hdr["dir_offset"]), "embedded pck in exe"


JS_TEMPLATE = """
var base = Process.getModuleByName(%(mod)r).base;
var rvas = %(rvas)s;
rvas.forEach(function(rva){
  try {
    Interceptor.attach(base.add(rva), {
      onEnter: function(){
        function hx(p){ try { var b=new Uint8Array(p.readByteArray(32)); var s='';
          for(var i=0;i<32;i++){ s+=('0'+b[i].toString(16)).slice(-2); } return s; } catch(e){ return null; } }
        send({ rva: rva, rcx: hx(this.context.rcx), rdx: hx(this.context.rdx),
               r8: hx(this.context.r8) });
      }
    });
  } catch(e){ send({err: ''+e, rva: rva}); }
});
send({ready:true, n: rvas.length});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("pck", nargs="?", default=None,
                    help="separate .pck (default: <exe>.pck if present, else embedded)")
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--rva", action="append", default=[],
                    help="explicit setkey RVA(s) in hex (repeatable); skips auto-locate")
    ap.add_argument("--loose", action="store_true",
                    help="high-recall RVA search (more candidates; verified, so safe)")
    args = ap.parse_args()

    import frida  # imported here so the file is importable without frida installed

    exe = os.path.abspath(args.exe)
    pck = args.pck or (os.path.splitext(exe)[0] + ".pck")

    fae, src = load_oracle(exe, pck)
    print("[*] oracle: %s (file_count=%d)" % (src, fae["file_count"]))

    data = open(exe, "rb").read()
    if args.rva:
        rvas = sorted({int(x, 16) for x in args.rva})
    else:
        rvas = find_setkey_entries(data, loose=args.loose)
    if not rvas:
        raise SystemExit(
            "No AES-NI setkey entries located. Either pass --rva, try --loose, or the\n"
            "build doesn't use the AES-NI key schedule (software/custom AES) — a hook on\n"
            "these entries can't catch the key. See docs/frida-key-hooking.md.")
    print("[*] hooking %d candidate AES-setkey entries: %s"
          % (len(rvas), ", ".join("0x%x" % r for r in rvas)))

    js = JS_TEMPLATE % {"mod": os.path.basename(exe), "rvas": str(rvas)}
    found, seen = {}, set()

    def on_message(msg, _data):
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        if p.get("ready"):
            print("[*] %d hooks installed; capturing..." % p.get("n", 0)); return
        if p.get("err"):
            return
        for reg in ("rdx", "rcx", "r8"):
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
    pid = dev.spawn([exe])
    sess = dev.attach(pid)
    scr = sess.create_script(js)
    scr.on("message", on_message)
    scr.load()
    dev.resume(pid)
    print("[*] spawned pid %d; capturing for %ds..." % (pid, args.seconds))
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
        print("\nNo key caught. Possible reasons:")
        print("  * the build uses software/custom AES (no AES-NI setkey) — these hooks")
        print("    are on the wrong routine; confirm with: python find_aes_rvas.py <exe>")
        print("  * the target never decrypted the pack in the capture window (e.g. it")
        print("    failed to start — offline / missing server key share, etc.)")
        print("  * the entry heuristic missed it — try --loose or pass --rva.")


if __name__ == "__main__":
    main()
