# Compiled GDScript (`.gdc`) format notes

Practical notes for working with Godot 4.x compiled-script bytecode, as used by
`carve_payloads.py` and `gdc_inspect.py`.

## Layout (observed, Godot 4.x, GDSC version 101)

```
offset  size  field
0       4     magic 'GDSC'
4       4     uint32  version            (e.g. 101)
8       4     uint32  decompressed_size  (size of the tokenizer buffer)
12      ...   zstd frame                 (the compressed tokenizer buffer)
```

The compressed payload is a standard **zstd frame** (magic `28 b5 2f fd`). Zstd
frames are **self-delimiting**, which has two useful consequences:

- You can decompress a blob that has **extra trailing bytes** (e.g. an
  over-carved blob that runs into the next file) — the decoder stops at the frame
  end and ignores the rest.
- You can recover the **exact `.gdc` length**: `12 + bytes_consumed_by_the_frame`.
  `gdc_inspect.py` reports this; it's what you need for a clean standalone GDRE
  decompile (which requires exact-length input).

## Source-level info leaks before full decompilation

The decompressed tokenizer buffer contains the script's **identifier table** and
**string literals** in cleartext. So an *unencrypted* `.gdc` leaks function/var
names and string content even without a real decompiler:

```bash
python gdc_inspect.py some.gdc --strings
```

This is why per-file encryption of scripts matters: it turns the whole `GDSC`
buffer (magic included) into ciphertext, so neither carving nor string-scraping
works.

## `GDSC` magic collisions

The 4-byte sequence `GDSC` also appears coincidentally inside other binary data
(textures, audio, resources). So a raw count of `GDSC` occurrences **overcounts**
real scripts. Validate each hit:

- real script: `version` is a small int **and** bytes at +12 are the zstd magic
- collision: fails one of those

`is_valid_gdc()` / `count_valid_scripts()` in `godot_pck_common.py` do this, and
it's how the tools report "valid compiled scripts" vs "byte-collisions."

## Carving exact vs superset

- **Compiled scripts:** carve from the `GDSC` magic, then trim to `exact_len`
  via the zstd frame → clean `.gdc`.
- **Other resource types** (`RSRC`, `GST2`, …): without the directory you don't
  know exact lengths, so carve up to the next signature (a superset that may
  include trailing bytes). Usually fine for inspection; not byte-exact.

> Format details are version-specific and based on observation of Godot 4.x
> builds; treat version/field specifics as "verify on your target," not gospel.

See also: [`gdre-notes.md`](gdre-notes.md) for decompiling these to `.gd`, and
[`how-pck-encryption-works.md`](how-pck-encryption-works.md) §5 for where `.gdc`
fits into extraction.
