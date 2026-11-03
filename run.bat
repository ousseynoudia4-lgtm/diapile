@echo off
REM ================================================================
REM DIAPILE — Script de lancement rapide (Windows)
REM Usage : run.bat [target1,target2,...] [options nrtg]
REM ================================================================
setlocal enabledelayedexpansion

echo.
echo   ██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗
echo   ██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝
echo   ██║  ██║██║███████║██████╔╝██║██║     █████╗
echo   ██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝
echo   ██████╔╝██║██║  ██║██║     ██║███████╗███████╗
echo   ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝
echo.
echo   Network Redteam Grapher v2.0 - Docker Runner
echo.

REM Charger .env si present
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
        if not "%%a"=="" if not "%%a:~0,1%"=="#" set "%%a=%%b"
    )
    echo [OK]  .env charge
) else (
    echo [WARN] .env absent - copiez .env.example en .env
)

REM Creer les dossiers de sortie
if not exist "out" mkdir out
if not exist "sessions" mkdir sessions

REM Verifier que l image existe
docker image inspect nrtg:latest >nul 2>&1
if errorlevel 1 (
    echo [BUILD] Image nrtg:latest absente - build en cours...
    docker build -t nrtg:latest -t nrtg:2.0.0 .
    echo [OK]  Image construite
)

REM Arguments passes au script
set "NRTG_ARGS=%*"
if "%NRTG_ARGS%"=="" set "NRTG_ARGS=--features"

REM Variables env a injecter
set "ENV_ARGS="
if defined OPENROUTER_API_KEY set "ENV_ARGS=%ENV_ARGS% -e OPENROUTER_API_KEY=%OPENROUTER_API_KEY%"
if defined OPENAI_API_KEY     set "ENV_ARGS=%ENV_ARGS% -e OPENAI_API_KEY=%OPENAI_API_KEY%"
if defined RUST_LOG           set "ENV_ARGS=%ENV_ARGS% -e RUST_LOG=%RUST_LOG%"

echo [RUN]  docker run nrtg %NRTG_ARGS%
echo.

docker run --rm ^
  -v "%CD%\out:/app/out" ^
  -v "%CD%\sessions:/app/sessions" ^
  %ENV_ARGS% ^
  nrtg:latest %NRTG_ARGS%

echo.
echo Sorties dans .\out\
dir /b out\graph.* 2>nul

endlocal
