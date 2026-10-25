@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
title Тест Launcher
color 0A

:: ── Поиск Python 3.11 ──────────────────────────────────────────
set PYTHON_EXE=
for %%p in ("%ProgramFiles%\Python311\python.exe" "%LocalAppData%\Programs\Python\Python311\python.exe") do (
    if not defined PYTHON_EXE if exist "%%p" set "PYTHON_EXE=%%p"
)
if not defined PYTHON_EXE for /d %%i in ("%ProgramFiles%\Python*") do if not defined PYTHON_EXE if exist "%%i\python.exe" (
    for /f "tokens=2" %%v in ('"%%i\python.exe" --version 2^>^&1') do echo %%v | findstr "^3\.11" >nul && set "PYTHON_EXE=%%i\python.exe"
)
if not defined PYTHON_EXE where python >nul 2>&1 (
    for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo %%v | findstr "^3\.11" >nul && set "PYTHON_EXE=python"
)

if not defined PYTHON_EXE (
    echo ERROR: Python 3.11 not found. Install it and run this script again.
    start https://www.python.org/downloads/release/python-3110/
    pause
    exit /b 1
)
echo [1/3] Python 3.11 found: %PYTHON_EXE%

:: ── Виртуальное окружение ──────────────────────────────────────
if exist ".venv\Scripts\python.exe" (
    echo [2/3] Virtualenv .venv already exists, skipping creation.
) else (
    echo [2/3] Creating virtualenv .venv ...
    %PYTHON_EXE% -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtualenv!
        pause
        exit /b 1
    )
)
call ".venv\Scripts\activate.bat"

:: ── Зависимости ────────────────────────────────────────────────
if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found!
    pause
    exit /b 1
)
echo [3/3] Upgrading pip ...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo ERROR: Failed to upgrade pip!
    pause
    exit /b 1
)
echo [3/3] Installing dependencies from requirements.txt ...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies!
    pause
    exit /b 1
)
echo [3/3] Dependencies are up to date.

pause