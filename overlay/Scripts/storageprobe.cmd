@echo off
rem storageprobe.cmd - PE storage / BSOD-rescue readiness probe. Just type: storageprobe
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\storageprobe.ps1" %*
