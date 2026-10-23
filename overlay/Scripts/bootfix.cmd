@echo off
rem bootfix.cmd - UEFI boot reconstruction + BOOTSTAT/Recovery cleanup chain. Type: bootfix -Check
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\bootfix.ps1" %*
