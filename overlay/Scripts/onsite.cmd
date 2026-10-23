@echo off
rem onsite.cmd - stick-root shim for Tools\onsite.ps1 (field storage-driver test + evidence bundle).
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
rem Lives at the root of the USB stick next to Tools\ and Storage\, so it must not be moved into System32.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Tools\onsite.ps1" %*
