@echo off
rem letterfix.cmd - persistent drive-letter repair via victim hive MountedDevices. Type: letterfix
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\letterfix.ps1" %*
