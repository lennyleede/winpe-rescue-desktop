@echo off
rem niccheck.cmd - PE on-site NIC/net self-check. Just type: niccheck
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\niccheck.ps1" %*
