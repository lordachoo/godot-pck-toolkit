@echo off
REM Menu-driven front-end for godot-pck-toolkit (Windows).
REM Authorized use only - your own builds or work you're permitted to analyze.
setlocal EnableDelayedExpansion
cd /d "%~dp0tools" || (echo cannot find tools\ & pause & exit /b 1)

set "PY=python"
where %PY% >nul 2>nul || set "PY=py"
set "OUT=..\out"
set "TARGET="

:menu
cls
echo =================== godot-pck-toolkit ===================
if defined TARGET (echo   target: !TARGET!) else (echo   target: ^<none - option 1 to set^>)
echo   output: %OUT%
echo --------------------------------------------------------
echo    1^) Set target exe/pck
echo    2^) Analyze            ^(overview + encryption verdict, no key^)
echo    3^) Check encryption   ^(defender audit, no key^)
echo    4^) Compare two builds ^(before/after, no key^)
echo    5^) Carve payloads     ^(report; optional --extract^)
echo    6^) Carve embedded PCK + header report
echo    7^) Recover key from the EXECUTABLE ^(static scan^)
echo    8^) Create memory dump ^(launches the game^)
echo    9^) Recover key from a MEMORY DUMP
echo   10^) Recover key by HOOKING a running game ^(Frida; beats key-wipe^)
echo   11^) Extract project    ^(needs key.bin^)
echo   12^) Inspect a .gdc file
echo   13^) Decompile via Godot RE Tools
echo   14^) Install Python dependencies
echo    q^) Quit
echo --------------------------------------------------------
set "c="
set /p "c=choice: "

if "%c%"=="1" ( set /p "TARGET=Path to game .exe or .pck: " & goto menu )
if "%c%"=="2" ( call :need & %PY% analyze.py "!TARGET!" & pause & goto menu )
if "%c%"=="3" ( call :need & %PY% check_encryption.py "!TARGET!" & pause & goto menu )
if "%c%"=="4" ( set /p "A=build A: " & set /p "B=build B: " & %PY% pck_compare.py "!A!" "!B!" & pause & goto menu )
if "%c%"=="5" ( call :need & set /p "D=extract dir (blank=report only): " & if defined D ( %PY% carve_payloads.py "!TARGET!" --extract "!D!" ) else ( %PY% carve_payloads.py "!TARGET!" ) & pause & goto menu )
if "%c%"=="6" ( call :need & %PY% extract_godot_pck.py "!TARGET!" --outdir "%OUT%" & pause & goto menu )
if "%c%"=="7" ( call :need & %PY% recover_godot_key.py "!TARGET!" --out "%OUT%\key.bin" & pause & goto menu )
if "%c%"=="8" ( call :need & set "DMP=%OUT%\game.dmp" & set /p "DMP=dump output [%OUT%\game.dmp]: " & powershell -ExecutionPolicy Bypass -File dump_game_memory.ps1 -Exe "!TARGET!" -Out "!DMP!" & pause & goto menu )
if "%c%"=="9" ( call :need & set /p "DMP=dump file (.dmp): " & %PY% extract_key_from_dump.py "!TARGET!" "!DMP!" --out "%OUT%\key.bin" & pause & goto menu )
if "%c%"=="10" ( call :need & set "S=30" & set /p "S=capture seconds [30]: " & %PY% frida_keycatch.py "!TARGET!" --seconds "!S!" & pause & goto menu )
if "%c%"=="11" ( call :need & set "K=%OUT%\key.bin" & set /p "K=key.bin [%OUT%\key.bin]: " & %PY% extract_godot_project.py "!TARGET!" --key "!K!" --out "%OUT%\project" & pause & goto menu )
if "%c%"=="12" ( set /p "G=.gdc file: " & %PY% gdc_inspect.py "!G!" --strings & pause & goto menu )
if "%c%"=="13" ( call :need & set /p "GDRE=path to gdre_tools.exe: " & set /p "HK=key (64 hex, blank if none): " & if defined HK ( %PY% decompile_gdc_batch.py --gdre "!GDRE!" --recover "!TARGET!" --key "!HK!" --out "%OUT%\recovered" ) else ( %PY% decompile_gdc_batch.py --gdre "!GDRE!" --recover "!TARGET!" --out "%OUT%\recovered" ) & pause & goto menu )
if "%c%"=="14" ( %PY% -m pip install -r ..\requirements.txt & pause & goto menu )
if /i "%c%"=="q" ( exit /b 0 )
goto menu

:need
if not defined TARGET set /p "TARGET=Path to game .exe or .pck: "
goto :eof
