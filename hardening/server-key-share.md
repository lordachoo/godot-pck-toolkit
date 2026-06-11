# Server-held PCK key share — reference implementation (Godot 4.6.1)

A reference design for splitting Godot's PCK encryption key so that **one share is
held by your server and only handed to the client at startup** (after it connects /
authenticates). The shipped binary then contains only `key ^ S` — useless on its
own — and the engine fetches `S` at boot, *before* the encrypted pack is mounted.

This raises the bar that `recover_godot_key.py` (static), `extract_key_from_dump.py`
(memory dump), and `frida_keycatch.py` (runtime hook of an **offline** run) rely on.
Read the honest scope before you build it.

> This is an **engine-source** change: you build a custom export template from the
> Godot 4.6.1-stable source, then export your game with it. Stock binaries can't do
> this. All names/ports/hosts below are placeholders — change them.

---

## How it works

```
real_key = ek_base ^ S
           └ baked ┘   └ from server ┘
```

- The build bakes `script_encryption_key = real_key ^ S` into the template, and a
  zero-filled `script_encryption_key_share[32]`.
- At startup the engine fetches `S` over the network and calls
  `apply_server_key_share(S)`, which XORs `S` back into `script_encryption_key`,
  restoring `real_key` — **only then** is the pack mounted and decrypted.
- No `S` (server down / build revoked / offline) ⇒ the key stays `real_key ^ S`
  ⇒ the pack won't decrypt ⇒ startup aborts (**fail-closed**).

**Opt-in / zero-impact when off:** everything is gated on the build env var
`GODOT_KEYSHARE_URL`. Unset ⇒ `S = 0`, no fetch, behaviour identical to a stock
build. Only setting it activates the split.

### Honest scope (read this)

| Attack | Stock encrypted build | With server key share |
|---|---|---|
| Reconstruct key from the binary (static) | works | **dead** — binary holds `key ^ S` |
| Run offline + memory dump / Frida hook | works | **dead** — no `S` ⇒ no key ever forms |
| **Authenticated/online user hooks their own session** | works | **still works** — gated, logged, revocable, per-build |

It does **not** stop a logged-in attacker from hooking their live session — AES must
have the key in memory to decrypt. What it buys: "trivial and offline for anyone" →
"online-only, attributable, and revocable." Layer it on top of the wipe/split-key
hardening in [`../docs/hardening.md`](../docs/hardening.md).

---

## Init ordering (why a raw socket, not `HTTPClient`/`StreamPeerTLS`)

The main pack is mounted very early in `Main::setup()` — **before** the networking
TLS module is initialized (`initialize_modules(MODULE_INITIALIZATION_LEVEL_CORE)`
runs later). So `StreamPeerTLS` / `HTTPClient` have no TLS backend at fetch time.

- For **HTTP** (LAN/testing) you can use `StreamPeerTCP` directly — it's registered
  in `register_core_types()`, which has already run.
- For **HTTPS** (production) drive the bundled **mbedtls directly** over a
  `StreamPeerTCP` transport (mbedtls BIO callbacks) and **pin the server cert**.
  That's more code than fits here; the HTTP version below is the core mechanism, and
  the TLS wrapper is a drop-in around the same send/recv.

---

## Files changed

| File | Change |
|---|---|
| `core/SCsub` | define `GODOT_KEYSHARE_ENABLED` when `GODOT_KEYSHARE_URL` is set (so the fetch only compiles for keyshare builds). |
| `core/core_builders.py` | in the encryption-key builder: fold `S` into the baked key (`key ^ S`); emit `script_encryption_key_share`, `apply_server_key_share()`, and `keyshare_url/build_id/pin` getters; write `build_keyshare.json`. No-op when `GODOT_KEYSHARE_URL` is unset. |
| `core/crypto/keyshare.h` / `keyshare.cpp` | **new** — the native pre-mount fetch (HTTP shown; TLS optional). Auto-compiled by `core/crypto/SCsub`. |
| `main/main.cpp` | call `fetch_and_apply_key_share()` in `Main::setup()` right before the main pack is mounted; **fail-closed**. Skipped in the editor. |

---

## 1) `core/SCsub`

Add near the encryption-key builder invocation:

```python
import os
# Server key share: only compile the native fetch when enabled, so a normal build
# stays byte-for-byte stock. crypto/SCsub clones this env, so the define reaches
# core/crypto/keyshare.cpp.
if os.environ.get("GODOT_KEYSHARE_URL"):
    env.Append(CPPDEFINES=["GODOT_KEYSHARE_ENABLED"])
    # Optional plaintext startup trace (keyshare.log next to the exe) for debugging.
    # Never enable for shipped builds.
    if os.environ.get("GODOT_KEYSHARE_DEBUG"):
        env.Append(CPPDEFINES=["GODOT_KEYSHARE_DEBUG"])
```

`core/crypto/` is globbed, so dropping `keyshare.cpp` there is enough to compile it.

---

## 2) `core/core_builders.py`

Augment the function that generates `script_encryption_key.gen.cpp` (stock reads the
key from the `SCRIPT_AES256_ENCRYPTION_KEY` env var). The additions:

```python
import os, json, struct

def make_encryption_key(target, source, env):
    # --- stock: get the real 32-byte key from SCRIPT_AES256_ENCRYPTION_KEY ---
    txt = "0" * 64
    src = os.environ.get("SCRIPT_AES256_ENCRYPTION_KEY", "")
    if src:
        if len(src) != 64:
            raise SystemExit("SCRIPT_AES256_ENCRYPTION_KEY must be 64 hex chars")
        txt = src
    key = bytes.fromhex(txt)

    # --- server key share (opt-in) -------------------------------------------
    url = os.environ.get("GODOT_KEYSHARE_URL", "").strip()
    pin = os.environ.get("GODOT_KEYSHARE_PIN", "").strip()        # hex sha256 of leaf cert ("" = none)
    enabled = bool(url)
    if enabled:
        S = os.urandom(32)
        build_id = os.environ.get("GODOT_KEYSHARE_BUILD_ID", "") or os.urandom(8).hex()
    else:
        S = bytes(32)        # all-zero -> key unchanged, identical to stock
        build_id = ""

    baked = bytes(b ^ s for b, s in zip(key, S))                 # script_encryption_key = key ^ S

    def arr(b):
        return ",".join(str(x) for x in b)

    def cstr(s):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    with open(target[0].path, "w") as f:
        f.write("#include \"core/crypto/keyshare.h\"\n")
        f.write("#include <stdint.h>\n\n")
        f.write("uint8_t script_encryption_key[32] = {%s};\n" % arr(baked))
        f.write("static uint8_t script_encryption_key_share[32] = {%s};\n\n" % arr(bytes(32)))
        # XOR the fetched share into the live key (key^S ^ S = key).
        f.write("void apply_server_key_share(const uint8_t p_share[32]) {\n")
        f.write("\tfor (int i = 0; i < 32; i++) { script_encryption_key[i] ^= p_share[i]; }\n")
        f.write("\t(void)script_encryption_key_share;\n}\n\n")
        f.write("static const char *_ks_url = %s;\n" % cstr(url))
        f.write("static const char *_ks_build = %s;\n" % cstr(build_id))
        f.write("static const char *_ks_pin = %s;\n" % cstr(pin))
        f.write("const char *keyshare_url() { return _ks_url; }\n")
        f.write("const char *keyshare_build_id() { return _ks_build; }\n")
        f.write("const char *keyshare_pin() { return _ks_pin; }\n")

    # Emit the share to register with the server, then DELETE this file. Secret.
    if enabled:
        with open(os.path.join(os.getcwd(), "build_keyshare.json"), "w") as kf:
            json.dump({"build_id": build_id, "share_hex": S.hex(), "url": url}, kf, indent=2)
```

> Add `build_keyshare.json` to `.gitignore` — it contains `S`.

---

## 3) `core/crypto/keyshare.h`

```cpp
#pragma once
#include "core/error/error_list.h"
#include <stdint.h>

// Defined in the generated script_encryption_key.gen.cpp:
void apply_server_key_share(const uint8_t p_share[32]);
const char *keyshare_url();
const char *keyshare_build_id();
const char *keyshare_pin();

// Defined in keyshare.cpp: fetch S and apply it (no-op if keyshare disabled).
Error fetch_and_apply_key_share();
```

---

## 4) `core/crypto/keyshare.cpp` (HTTP reference)

The whole thing is gated on `GODOT_KEYSHARE_ENABLED`; otherwise it's a no-op stub so
normal builds carry no dependency on it. Two non-obvious correctness points are
baked in (both cost a day if you miss them):

- **Resolve the hostname.** `StreamPeerTCP::connect_to_host()` takes an `IPAddress`,
  not a string — `localhost`/DNS names must go through `IP::resolve_hostname()`.
- **Delay between polls.** The send/recv poll loops must sleep (~5 ms) per iteration,
  or they spin through their timeout budget in ~1 ms and return an empty body before
  the server can answer.

```cpp
#include "keyshare.h"

#ifdef GODOT_KEYSHARE_ENABLED

#include "core/io/ip.h"
#include "core/io/json.h"
#include "core/io/stream_peer_tcp.h"
#include "core/os/os.h"
#include "core/string/ustring.h"
#include "core/variant/variant.h"

static const int MAX_POLLS = 2000; // ~10s @ 5ms

static bool parse_url(const String &u, String &host, int &port, String &path) {
    if (!u.begins_with("http://")) {
        return false; // HTTP reference only; see the TLS note for https.
    }
    String s = u.substr(7);
    int slash = s.find("/");
    String authority = slash == -1 ? s : s.substr(0, slash);
    path = slash == -1 ? "/" : s.substr(slash);
    int colon = authority.find(":");
    if (colon == -1) {
        host = authority; port = 80;
    } else {
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1).to_int();
    }
    return !host.is_empty() && port > 0;
}

Error fetch_and_apply_key_share() {
    const String url = String::utf8(keyshare_url());
    if (url.is_empty()) {
        return OK; // keyshare disabled for this build.
    }

    String host, path;
    int port = 0;
    if (!parse_url(url, host, port, path)) {
        ERR_PRINT("keyshare: bad URL");
        return ERR_INVALID_PARAMETER;
    }

    IPAddress ip = host.is_valid_ip_address() ? IPAddress(host)
                 : IP::get_singleton()->resolve_hostname(host);
    if (!ip.is_valid()) {
        ERR_PRINT("keyshare: cannot resolve host");
        return ERR_CANT_RESOLVE;
    }

    Ref<StreamPeerTCP> tcp;
    tcp.instantiate();
    if (tcp->connect_to_host(ip, port) != OK) {
        return ERR_CANT_CONNECT;
    }
    for (int i = 0; i < 1000 && tcp->get_status() == StreamPeerTCP::STATUS_CONNECTING; i++) {
        tcp->poll();
        OS::get_singleton()->delay_usec(10000);
    }
    if (tcp->get_status() != StreamPeerTCP::STATUS_CONNECTED) {
        return ERR_CANT_CONNECT;
    }
    tcp->set_no_delay(true);

    // Minimal install identity + nonce (replace with your auth as needed).
    String client_token = OS::get_singleton()->get_unique_id();
    if (client_token.is_empty()) { client_token = "anon"; }
    String body = "{\"build_id\":\"" + String::utf8(keyshare_build_id()) +
                  "\",\"client_token\":\"" + client_token + "\"}";
    CharString body_utf8 = body.utf8();

    String req = "POST " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + itos(body_utf8.length()) + "\r\n";
    req += "Connection: close\r\n\r\n";
    req += body;
    CharString req_utf8 = req.utf8();

    // send all
    int sent_total = 0, polls = 0;
    const uint8_t *p = (const uint8_t *)req_utf8.get_data();
    int len = req_utf8.length();
    while (sent_total < len) {
        int sent = 0;
        if (tcp->put_partial_data(p + sent_total, len - sent_total, sent) != OK) {
            return FAILED;
        }
        if (sent == 0) {
            if (++polls > MAX_POLLS) return FAILED;
            tcp->poll();
            OS::get_singleton()->delay_usec(5000);
            continue;
        }
        sent_total += sent;
    }

    // read all (server uses Connection: close)
    String resp;
    uint8_t rb[1024];
    polls = 0;
    while (true) {
        tcp->poll();
        int got = 0;
        Error err = tcp->get_partial_data(rb, sizeof(rb), got);
        if (err != OK) break; // peer closed
        if (got == 0) {
            if (tcp->get_status() != StreamPeerTCP::STATUS_CONNECTED) break;
            if (++polls > MAX_POLLS) break;
            OS::get_singleton()->delay_usec(5000);
            continue;
        }
        resp += String::utf8((const char *)rb, got);
    }
    tcp->disconnect_from_host();

    int sep = resp.find("\r\n\r\n");
    String json_body = sep == -1 ? resp : resp.substr(sep + 4);
    JSON json;
    if (json.parse(json_body) != OK) {
        ERR_PRINT("keyshare: bad JSON response");
        return FAILED;
    }
    Dictionary d = json.get_data();
    if (!d.has("share")) {
        ERR_PRINT("keyshare: server denied");
        return FAILED;
    }
    String share_hex = d["share"];
    if (share_hex.length() != 64) {
        return FAILED;
    }
    uint8_t share[32];
    for (int i = 0; i < 32; i++) {
        share[i] = (uint8_t)share_hex.substr(i * 2, 2).hex_to_int();
    }
    apply_server_key_share(share);
    memset(share, 0, sizeof(share));
    return OK;
}

#else // GODOT_KEYSHARE_ENABLED

Error fetch_and_apply_key_share() { return OK; } // no-op for normal builds

#endif
```

> **HTTPS:** wrap the same send/recv in a bundled-mbedtls TLS session over the
> `StreamPeerTCP` (mbedtls BIO callbacks), verify the peer leaf cert's SHA-256
> against `keyshare_pin()`, and accept only `https://`. The plaintext HTTP path
> above sends the share in the clear — fine for a trusted LAN test, not production.

---

## 5) `main/main.cpp`

Include the header near the top:

```cpp
#include "core/crypto/keyshare.h"
```

In `Main::setup()`, **immediately before the main pack is mounted** (the
`ProjectSettings`/`_load_main_pack` step) and after the editor check, fail-closed:

```cpp
if (!editor) {
    if (fetch_and_apply_key_share() != OK) {
        OS::get_singleton()->print("Could not obtain key share — cannot start.\n");
        goto error; // fail closed: never mount the pack with the wrong key
    }
}
```

The editor is skipped so the project still opens normally for development.

---

## 6) Server — `keyshare_server.py` (reference)

Single file: daemon + admin CLI, SQLite store. Holds **only shares** (never the
real key), so a server breach yields values useless without the matching client
binaries. Terminate TLS at a reverse proxy (Caddy/nginx) or pass certs directly.
Ports/paths are placeholders.

```python
#!/usr/bin/env python3
"""Reference PCK key-share daemon + admin CLI. Placeholders — change everything."""
import argparse, datetime, os, sqlite3, secrets, sys

DB = os.environ.get("KEYSHARE_DB", "keyshare.db")
PORT = int(os.environ.get("KEYSHARE_PORT", "9000"))   # placeholder

def now(): return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    db().executescript("""
        CREATE TABLE IF NOT EXISTS builds(
            build_id TEXT PRIMARY KEY, share_hex TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tokens(
            token TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active',
            first_seen TEXT, last_seen TEXT, req_count INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit(ts TEXT, build_id TEXT, token TEXT, ip TEXT, result TEXT);
    """); 

def handle(build_id, token, ip):
    c = db()
    try:
        b = c.execute("SELECT * FROM builds WHERE build_id=?", (build_id,)).fetchone()
        t = c.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
        if t is None and token:  # trust-on-first-use: log every install, revocable later
            c.execute("INSERT INTO tokens(token,status,first_seen,last_seen,req_count)"
                      " VALUES(?,'active',?,?,0)", (token, now(), now()))
            t = c.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
        ok = (b and b["status"] == "active" and t and t["status"] == "active")
        result = "ok" if ok else ("no-build" if not b else
                  "build-revoked" if b["status"] != "active" else "token-revoked")
        c.execute("INSERT INTO audit VALUES(?,?,?,?,?)", (now(), build_id, token, ip, result))
        if t: c.execute("UPDATE tokens SET last_seen=?, req_count=req_count+1 WHERE token=?", (now(), token))
        c.commit()
        return (200, {"share": b["share_hex"]}) if ok else (403, {"error": result})
    finally:
        c.close()

def serve(host, port, certfile=None, keyfile=None):
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
    init()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    class Req(BaseModel):
        build_id: str
        client_token: str = ""
    @app.get("/healthz")
    def healthz(): return {"ok": True}
    @app.post("/v1/keyshare")
    def keyshare(r: Req, request: Request):
        ip = request.client.host if request.client else "?"
        code, payload = handle(r.build_id, r.client_token, ip)
        return JSONResponse(status_code=code, content=payload)
    uvicorn.run(app, host=host, port=port, ssl_certfile=certfile, ssl_keyfile=keyfile)

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=PORT)
    s.add_argument("--ssl-certfile"); s.add_argument("--ssl-keyfile")
    sub.add_parser("init-db")
    a = sub.add_parser("add-build"); a.add_argument("build_id"); a.add_argument("share_hex")
    sub.add_parser("list-builds")
    r = sub.add_parser("revoke-build"); r.add_argument("build_id")
    rt = sub.add_parser("revoke-token"); rt.add_argument("token")
    tl = sub.add_parser("tail-log"); tl.add_argument("-n", type=int, default=50)
    args = p.parse_args()
    if args.cmd == "serve": serve(args.host, args.port, args.ssl_certfile, args.ssl_keyfile)
    elif args.cmd == "init-db": init(); print("initialized", DB)
    elif args.cmd == "add-build":
        if len(bytes.fromhex(args.share_hex)) != 32: sys.exit("share must be 32 bytes")
        init(); c = db()
        c.execute("INSERT OR REPLACE INTO builds(build_id,share_hex,status,created_at)"
                  " VALUES(?,?,'active',?)", (args.build_id, args.share_hex.lower(), now()))
        c.commit(); print("added", args.build_id)
    elif args.cmd == "list-builds":
        init()
        for r in db().execute("SELECT * FROM builds ORDER BY created_at DESC"):
            print(r["status"], r["build_id"], r["share_hex"][:12] + "...", r["created_at"])
    elif args.cmd == "revoke-build":
        c = db(); c.execute("UPDATE builds SET status='revoked' WHERE build_id=?", (args.build_id,))
        c.commit(); print("revoked", args.build_id)
    elif args.cmd == "revoke-token":
        c = db(); c.execute("UPDATE tokens SET status='revoked' WHERE token=?", (args.token,))
        c.commit(); print("revoked", args.token)
    elif args.cmd == "tail-log":
        init()
        for r in reversed(db().execute("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (args.n,)).fetchall()):
            print(r["ts"], r["result"], r["build_id"], r["ip"])

if __name__ == "__main__":
    main()
```

`pip install fastapi uvicorn pydantic`. API:

```
POST /v1/keyshare   body: {"build_id":"...","client_token":"<install-id>"}
  -> 200 {"share":"<64 hex>"}   |   403 {"error":"no-build|build-revoked|token-revoked"}
GET  /healthz       -> {"ok":true}
```

---

## Build & release procedure

```bash
# 1) Server: register the build's share (generated by the template build, below)
python keyshare_server.py init-db
python keyshare_server.py serve --host 127.0.0.1 --port 9000     # placeholder port

# 2) Build the custom template (env vars in the SAME shell that runs scons)
export SCRIPT_AES256_ENCRYPTION_KEY=<64 hex real key>
export GODOT_KEYSHARE_URL="http://127.0.0.1:9000/v1/keyshare"     # https for prod
# export GODOT_KEYSHARE_PIN=<sha256 of server leaf cert>          # https only
scons platform=windows target=template_release arch=x86_64
#   -> writes build_keyshare.json = { build_id, share_hex }
python keyshare_server.py add-build  "$(jq -r .build_id build_keyshare.json)" \
                                     "$(jq -r .share_hex build_keyshare.json)"
#   then DELETE build_keyshare.json (it's the secret S)

# 3) Export your game with this custom template, using the SAME encryption key.
# 4) Retire a build later:  python keyshare_server.py revoke-build <build_id>
```

---

## Testing & gotchas

- **Disabled = stock.** Build without `GODOT_KEYSHARE_URL` → runs exactly as a
  normal encrypted build (regression check).
- **Enabled, server up, share registered** → game launches normally.
- **Enabled, server down / build revoked** → game **fails to start** (the win).
- **Offline reconstruction** → point `recover_godot_key.py` / `carve` at the build:
  the baked key is `key ^ S`, so it recovers nothing usable.
- **Env vars don't cross shells.** Set them in the *same* shell that runs `scons`.
- **Force regeneration.** Changing a key/URL may not retrigger SCons — delete the
  generated `core/script_encryption_key.gen.cpp` and rebuild if it says "up to date".
- **No `.console.exe` for release** and the fetch runs before engine logging — build
  with `GODOT_KEYSHARE_DEBUG=1` to get a `keyshare.log` next to the exe while
  debugging (never ship it).

---

## Limitations

- The client credential is pre-login and extractable from the binary; defense is
  rate-limit + detection + revocation on the server, not credential secrecy.
- Plain HTTP leaks `S` on the wire — use HTTPS + cert pinning for anything real.
- Does not stop an authenticated, online attacker hooking their own session (see
  scope table). Pair with the in-memory hardening in
  [`../docs/hardening.md`](../docs/hardening.md) and
  [`../docs/frida-key-hooking.md`](../docs/frida-key-hooking.md).
