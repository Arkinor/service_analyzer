@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

REM ==== Настройки ====
set APP_NAME=service_analyzer
set SCRIPT_NAME=service_analyzer.py
set VENV_DIR=.venv
set ICON_FILE=icon.ico
REM ====================

echo [1/7] Проверка Python...
where python >nul 2>nul
if errorlevel 1 (
    echo [ОШИБКА] Python не найден в PATH. Установите Python 3.11 и добавьте его в PATH.
    pause
    exit /b 1
)
python --version
echo.

echo [2/7] Создание виртуального окружения "%VENV_DIR%"...
if not exist "%VENV_DIR%" (
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ОШИБКА] Не удалось создать venv.
        pause
        exit /b 1
    )
) else (
    echo Виртуальное окружение уже существует, пропускаем.
)
echo.

echo [3/7] Активация venv...
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [ОШИБКА] Не удалось активировать venv.
    pause
    exit /b 1
)
echo.

echo [4/7] Обновление pip / setuptools / wheel...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo [ОШИБКА] Не удалось обновить pip.
    pause
    exit /b 1
)
echo.

echo [5/7] Установка зависимостей из requirements.txt...
if not exist "requirements.txt" (
    echo [ОШИБКА] Файл requirements.txt не найден рядом с build.bat.
    pause
    exit /b 1
)
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить зависимости.
    pause
    exit /b 1
)
echo.

echo [6/7] Установка PyInstaller...
python -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить PyInstaller.
    pause
    exit /b 1
)
echo.

echo [7/7] Сборка %APP_NAME%.exe...
set ICON_ARG=
if exist "%ICON_FILE%" (
    set ICON_ARG=--icon "%ICON_FILE%"
    echo Используется иконка: %ICON_FILE%
) else (
    echo Иконка %ICON_FILE% не найдена — сборка без иконки.
)

pyinstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --noconsole ^
    --uac-admin ^
    --name "%APP_NAME%" ^
    %ICON_ARG% ^
    --hidden-import psutil ^
    --collect-submodules psutil ^
    --collect-submodules analyzer ^
    "%SCRIPT_NAME%"

if errorlevel 1 (
    echo.
    echo [ОШИБКА] Сборка не удалась. Смотрите вывод выше.
    pause
    exit /b 1
)

echo.
echo ==================================================
echo  Готово! Файл: dist\%APP_NAME%.exe
echo ==================================================
echo.

REM Открываем папку с результатом
if exist "dist" (
    explorer "dist"
)

pause
endlocal