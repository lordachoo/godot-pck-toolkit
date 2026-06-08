<#
dump_game_memory.ps1 — launch a Godot game, let it mount/decrypt its PCK (the
key enters RAM at engine init), then write a full-memory minidump and kill it.

The encrypted PCK is mounted during engine startup, before the main scene and
before any network/login, so a few seconds of runtime is enough to capture the
cleartext key in memory.

Usage:
  powershell -ExecutionPolicy Bypass -File dump_game_memory.ps1 `
      -Exe "C:\path\to\your_game.exe" `
      -Out "C:\path\to\game.dmp" `
      -WaitSeconds 12
#>
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Out,
  [int]$WaitSeconds = 12
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class MiniDumper {
  [DllImport("dbghelp.dll", SetLastError=true)]
  public static extern bool MiniDumpWriteDump(
    IntPtr hProcess, uint ProcessId, IntPtr hFile,
    int DumpType, IntPtr Exception, IntPtr UserStream, IntPtr Callback);
}
"@

$ErrorActionPreference = "Stop"
$workdir = Split-Path -Parent $Exe
Write-Output "Launching $Exe ..."
$proc = Start-Process -FilePath $Exe -WorkingDirectory $workdir -PassThru
Start-Sleep -Seconds 2

# Pick the most memory-hungry process in the tree (the actual game window proc).
$candidates = @($proc)
try { $candidates += Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($Exe)) -ErrorAction SilentlyContinue } catch {}
Write-Output "Waiting $WaitSeconds s for engine init / PCK mount ..."
Start-Sleep -Seconds $WaitSeconds

$candidates = $candidates | Where-Object { $_ -and -not $_.HasExited } | Sort-Object WorkingSet64 -Descending
if (-not $candidates) { throw "Game process exited before dump (needs a server/login?)." }
$target = $candidates[0]
$target.Refresh()
Write-Output ("Dumping PID {0}  ({1:N0} MB working set) -> {2}" -f $target.Id, ($target.WorkingSet64/1MB), $Out)

$fs = [System.IO.File]::Create($Out)
try {
  $ok = [MiniDumper]::MiniDumpWriteDump($target.Handle, [uint32]$target.Id, $fs.SafeFileHandle.DangerousGetHandle(), 0x2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
  $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
} finally { $fs.Close() }

if (-not $ok) {
  Write-Output "MiniDumpWriteDump failed (win32 err=$err); trying comsvcs fallback..."
  & rundll32.exe comsvcs.dll, MiniDump $target.Id $Out full
}

# Clean up the game.
try { Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue } catch {}
try { Stop-Process -Id $proc.Id  -Force -ErrorAction SilentlyContinue } catch {}

if (Test-Path $Out) {
  Write-Output ("Dump written: {0:N0} bytes" -f (Get-Item $Out).Length)
} else {
  throw "Dump file was not created."
}
