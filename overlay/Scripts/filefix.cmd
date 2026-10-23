@echo off
rem filefix.cmd - offline system-file repair ladder (sfc -> baseline restore -> sfc verify).
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\filefix.ps1" %*
