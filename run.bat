@echo off
REM PromptReaper - lanzador rapido (Windows)
REM Uso:  run.bat engagements\lab-vulnerable.json [--no-llm]
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Uso: run.bat ^<engagement.json^> [opciones]
  echo Ejemplo: run.bat engagements\lab-vulnerable.json --no-llm
  exit /b 2
)
python reaper.py %*
