@echo off
rem pe_getdriver.cmd - fetch a driver cab from the public catalog inside PE, expand, stage with pnputil.
rem Just type: pe_getdriver   (or: pe_getdriver -Url https://catalog.s.download.../xxx.cab -Dir X:\drv)
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\pe_getdriver.ps1" %*
