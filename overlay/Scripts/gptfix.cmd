@echo off
rem gptfix.cmd - GPT partition-table survey/repair (in-disk rebuild or gptdump restore). Type: gptfix
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\gptfix.ps1" %*
