"""
extract_godot_pck.py — carve the embedded Godot PCK out of a PE executable and
write a header report. Does not require the key (header/trailer are plaintext).

Usage:  python extract_godot_pck.py <exe> [--outdir ../extracted_pck]
"""
import os
import json
import struct
import argparse
import godot_pck_common as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--outdir", default="../extracted_pck")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    data = open(args.exe, "rb").read()
    pck_start = g.find_embedded_pck_start(data)
    embedded_size = struct.unpack_from("<Q", data, len(data) - 12)[0]
    pck_end = len(data) - 12  # data before the [u64 size]['GDPC'] trailer
    pck_bytes = data[pck_start:pck_end]

    hdr = g.parse_pck_header(data, pck_start)
    fae = g.read_dir_fae_header(data, hdr["dir_offset"])

    carved = os.path.join(args.outdir, "embedded.pck")
    with open(carved, "wb") as f:
        f.write(pck_bytes)

    report = {
        "source_exe": os.path.abspath(args.exe),
        "exe_size": len(data),
        "pck_start": pck_start,
        "pck_end": pck_end,
        "pck_size": len(pck_bytes),
        "trailer_declared_size": embedded_size,
        "pack_format_version": hdr["version"],
        "godot_version": "%d.%d.%d" % hdr["godot"],
        "pack_flags": hdr["flags"],
        "dir_encrypted": hdr["dir_encrypted"],
        "rel_filebase": hdr["rel_filebase"],
        "sparse_bundle": hdr["sparse_bundle"],
        "file_base": hdr["file_base"],
        "dir_offset": hdr["dir_offset"],
        "file_count": fae["file_count"],
        "dir_blob_length": fae["length"],
        "dir_blob_md5": fae["md5"].hex(),
        "dir_blob_iv": fae["iv"].hex(),
        "carved_pck": os.path.abspath(carved),
    }
    rp = os.path.join(args.outdir, "pck_report.json")
    json.dump(report, open(rp, "w"), indent=2)
    print(json.dumps(report, indent=2))
    print("\nReport: " + rp)


if __name__ == "__main__":
    main()
