# Layer 2: split-key storage (remove the resident raw key)

This removes problem **#1** from [`README.md`](README.md): the raw
`script_encryption_key[32]` global the build compiles into the engine. We replace
it with **three XOR shares** reconstructed on demand, so no single 32-byte key
exists in the binary or in RAM at rest.

This touches the **build** (how the key is compiled in), so it's a recipe rather
than a single drop-in patch — the exact spots vary slightly by engine version.
Pair it with the Layer 1 wipe patch (otherwise the *reconstructed* key still
lingers) and verify with the toolkit.

## How the key is compiled in (stock)

`core/SCsub` runs `core_builders.encryption_key_builder`, which writes
`script_encryption_key.gen.cpp`:

```cpp
#include "core/config/project_settings.h"
uint8_t script_encryption_key[32] = { /* raw 32 bytes */ };
```

That literal is the resident raw key. Stock `file_access_pack.cpp` then copies it:

```cpp
for (int i = 0; i < key.size(); i++) {
    key.write[i] = script_encryption_key[i];   // reads the resident raw global
}
```

## The change

### 1. Stop the build emitting the raw key — emit shares instead

Modify `core_builders.encryption_key_builder` (in `core/core_builders.py`) so the
raw key is never written; instead emit a zeroed symbol (to keep the name
resolving) plus three random shares:

```python
def encryption_key_builder(target, source, env):
    import secrets
    src = source[0].read() or "0" * 64
    key = bytes.fromhex(src)            # (keep the stock 64-hex validation)
    a = secrets.token_bytes(32)
    b = secrets.token_bytes(32)
    c = bytes(k ^ x ^ y for k, x, y in zip(key, a, b))   # a^b^c == key
    fmt = lambda buf: ", ".join(str(x) for x in buf)
    with methods.generated_wrapper(str(target[0])) as file:
        file.write(f'''#include "core/config/project_settings.h"
// Raw key intentionally NOT stored; reconstructed from shares at point of use.
uint8_t script_encryption_key[32] = {{ 0 }};
const uint8_t script_encryption_key_shares[3][32] = {{
    {{ {fmt(a)} }},
    {{ {fmt(b)} }},
    {{ {fmt(c)} }},
}};''')
```

Random shares are regenerated every build — fine, even desirable. The developer's
workflow is unchanged: they still set `SCRIPT_AES256_ENCRYPTION_KEY` as before.

### 2. Declare the shares

Find the existing declaration of the key (grep the tree for
`script_encryption_key` — in 4.6.1 it's an `extern` visible to
`file_access_pack.cpp`) and add alongside it:

```cpp
extern const uint8_t script_encryption_key_shares[3][32];
```

### 3. Reconstruct from shares at the use sites

In `file_access_pack.cpp`, at **both** decryption sites, replace the copy from the
raw global with a reconstruct from shares:

```cpp
for (int i = 0; i < key.size(); i++) {
    key.write[i] = script_encryption_key_shares[0][i]
                 ^ script_encryption_key_shares[1][i]
                 ^ script_encryption_key_shares[2][i];
}
```

The Layer 1 patch already adds the `secure_zero(key...)` immediately after
`open_and_parse` at these sites, so the reconstructed key is wiped after use.

> If you prefer not to touch the build, generate the shares header manually with
> [`split_key.py`](split_key.py) and `#include` it instead of using
> `script_encryption_key_shares` — but you must still ensure the build does **not**
> compile the real key into `script_encryption_key` (step 1), or the raw global
> remains resident and this is pointless.

## Why this matters (and what it doesn't fix)

- After this, a static disk scan finds only shares; a memory dump finds only
  shares plus the briefly-reconstructed key (wiped by Layer 1). The blind
  dump-and-scan for a contiguous 32-byte key fails.
- It does **not** stop an attacker who hooks the reconstruct/decrypt call at
  runtime, nor the lazy-load transient window. That needs white-box AES.

## Verify
Rebuild the template, re-export, then run the dump scan from
[`README.md`](README.md). Empty result at align-1 = success.
