@echo off
rem rescue.cmd - one-command BSOD / black-screen evidence bundle. Just type: rescue
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\rescue.ps1" %*
