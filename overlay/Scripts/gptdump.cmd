@echo off
rem gptdump.cmd - read-only GPT byte capture (rescue SOP step zero, feeds gptfix -DumpDir). Type: gptdump
rem ASCII only on purpose: cmd.exe reads .cmd as CP936, non-ASCII comments become garbage commands.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\System32\gptdump.ps1" %*
