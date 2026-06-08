#!/usr/bin/env bash
# Menu-driven front-end for godot-pck-toolkit.
# Authorized use only — your own builds or work you're permitted to analyze.
set -u
cd "$(dirname "$0")/tools" || { echo "cannot find tools/"; exit 1; }

PY="${PYTHON:-python}"
command -v "$PY" >/dev/null 2>&1 || PY=python3
OUT="../out"
TARGET=""

pause()  { read -rp "
Press Enter to continue..."; }
need()   { [ -n "$TARGET" ] || read -rp "Path to game .exe or .pck: " TARGET; }

while true; do
  clear
  echo "=================== godot-pck-toolkit ==================="
  echo "  target: ${TARGET:-<none — option 1 to set>}"
  echo "  output: $OUT"
  echo "--------------------------------------------------------"
  echo "   1) Set target exe/pck"
  echo "   2) Analyze            (overview + encryption verdict, no key)"
  echo "   3) Check encryption   (defender audit, no key)"
  echo "   4) Compare two builds (before/after, no key)"
  echo "   5) Carve payloads     (report; optional --extract)"
  echo "   6) Carve embedded PCK + header report"
  echo "   7) Recover key from the EXECUTABLE (static scan)"
  echo "   8) Create memory dump (launches the game — Windows)"
  echo "   9) Recover key from a MEMORY DUMP"
  echo "  10) Recover key by HOOKING a running game (Frida; beats key-wipe)"
  echo "  11) Extract project    (needs key.bin)"
  echo "  12) Inspect a .gdc file"
  echo "  13) Decompile via Godot RE Tools"
  echo "  14) Install Python dependencies"
  echo "   q) Quit"
  echo "--------------------------------------------------------"
  read -rp "choice: " c
  case "$c" in
    1) read -rp "Path to game .exe or .pck: " TARGET ;;
    2) need; "$PY" analyze.py "$TARGET"; pause ;;
    3) need; "$PY" check_encryption.py "$TARGET"; pause ;;
    4) read -rp "build A: " A; read -rp "build B: " B; "$PY" pck_compare.py "$A" "$B"; pause ;;
    5) need; read -rp "extract dir (blank = report only): " D
       if [ -n "$D" ]; then "$PY" carve_payloads.py "$TARGET" --extract "$D"; else "$PY" carve_payloads.py "$TARGET"; fi; pause ;;
    6) need; "$PY" extract_godot_pck.py "$TARGET" --outdir "$OUT"; pause ;;
    7) need; "$PY" recover_godot_key.py "$TARGET" --out "$OUT/key.bin"; pause ;;
    8) need; read -rp "dump output path [$OUT/game.dmp]: " DMP; DMP="${DMP:-$OUT/game.dmp}"
       powershell -ExecutionPolicy Bypass -File dump_game_memory.ps1 -Exe "$TARGET" -Out "$DMP"; pause ;;
    9) need; read -rp "dump file (.dmp): " DMP; "$PY" extract_key_from_dump.py "$TARGET" "$DMP" --out "$OUT/key.bin"; pause ;;
    10) need; read -rp "capture seconds [30]: " S; S="${S:-30}"
        "$PY" frida_keycatch.py "$TARGET" --seconds "$S"; pause ;;
    11) need; read -rp "key.bin [$OUT/key.bin]: " K; K="${K:-$OUT/key.bin}"
        "$PY" extract_godot_project.py "$TARGET" --key "$K" --out "$OUT/project"; pause ;;
    12) read -rp ".gdc file: " G; "$PY" gdc_inspect.py "$G" --strings; pause ;;
    13) need; read -rp "path to gdre_tools.exe: " GDRE; read -rp "key (64 hex, blank if none): " HK
        if [ -n "$HK" ]; then "$PY" decompile_gdc_batch.py --gdre "$GDRE" --recover "$TARGET" --key "$HK" --out "$OUT/recovered"
        else "$PY" decompile_gdc_batch.py --gdre "$GDRE" --recover "$TARGET" --out "$OUT/recovered"; fi; pause ;;
    14) "$PY" -m pip install -r ../requirements.txt; pause ;;
    q|Q) exit 0 ;;
    *) ;;
  esac
done
