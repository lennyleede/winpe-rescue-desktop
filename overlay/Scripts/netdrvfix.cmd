@echo off
rem netdrvfix.cmd - repair broken NICs AND storage controllers WinPE PnP left unbound (code18: pnputil remove-device+scan, code28: drvload/add-driver). Just type: netdrvfix
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\netdrvfix.ps1" %*
