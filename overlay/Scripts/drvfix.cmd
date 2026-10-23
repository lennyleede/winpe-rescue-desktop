@echo off
rem drvfix.cmd - offline SYSTEM-hive surgery on boot-critical driver services. Type: drvfix
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\drvfix.ps1" %*
