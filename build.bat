@echo off
@setlocal EnableDelayedExpansion

pushd "%~dp0" >nul

@set OUTPUT_NAME=InsydeGerritCodeDownloader
@set OUTPUT_FILE_NAME=%OUTPUT_NAME%.exe
@set VENV_DIR=.venv-win
@set ENTRY_POINT=src\InsydeGerritCodeDownloader\__main__.py

if /I "%~1"=="/clean" goto :clean
if /I "%~1"=="clean" goto :clean
if /I "%~1"=="/?" goto :usage
if /I "%~1"=="-h" goto :usage
if /I "%~1"=="--help" goto :usage

@REM Check Python version
@set MAJOR_VERSION=0
@set MINOR_VERSION=0
@set GET_PYTHON_VERSION="import sys; print('%%d.%%d' %% (sys.version_info[0], sys.version_info[1]))"
for /f "tokens=1,2 delims=." %%a in ('py -c %GET_PYTHON_VERSION%') do (
@   set MAJOR_VERSION=%%a
@   set MINOR_VERSION=%%b
)

@set VERSION_OK=1
if !MAJOR_VERSION! LSS 3 (
@   set VERSION_OK=0
) else if !MAJOR_VERSION! EQU 3 if !MINOR_VERSION! LSS 12 (
@   set VERSION_OK=0
)
if !VERSION_OK! NEQ 1 (
@   echo [ERROR] Python 3.12 or higher is required.
    popd >nul
    exit /b 1
)

@REM Start Python Virtual Environment
if not exist "%VENV_DIR%" (
    echo [INFO] Creating Python Virtual Environment in %VENV_DIR%
    py -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create Python Virtual Environment.
        popd >nul
        exit /b 1
    )
)
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Failed to activate Python Virtual Environment.
    popd >nul
    exit /b 1
)

@REM Ensure PyInstaller and 3rd party modules are installed
python -m pip install --upgrade pip
if errorlevel 1 goto :error

if exist requirements.txt (
    python -m pip install -r requirements.txt
    if errorlevel 1 goto :error
) else (
    echo [ERROR] requirements.txt was not found.
    goto :error
)

@REM Build Windows executable and copy to workspace
if exist "%OUTPUT_FILE_NAME%" del /q "%OUTPUT_FILE_NAME%"

echo [INFO] Start generating %OUTPUT_FILE_NAME%
pyinstaller -F "%ENTRY_POINT%" -n "%OUTPUT_NAME%" --paths src --collect-data colorful --upx-exclude python3.dll
if errorlevel 1 goto :error

if exist "dist\%OUTPUT_FILE_NAME%" (
    copy /y "dist\%OUTPUT_FILE_NAME%" "%OUTPUT_FILE_NAME%" >nul
    echo [INFO] Copied dist\%OUTPUT_FILE_NAME% to %OUTPUT_FILE_NAME%
) else (
    echo [ERROR] Failed to find dist\%OUTPUT_FILE_NAME%.
    goto :error
)

@REM Remove build\, dist\, and generated *.spec file
if exist build rmdir /q /s build
if exist dist rmdir /q /s dist
if exist "%OUTPUT_NAME%.spec" del /q "%OUTPUT_NAME%.spec"
if exist "%OUTPUT_FILE_NAME%.spec" del /q "%OUTPUT_FILE_NAME%.spec"

deactivate
popd >nul
exit /b 0

:usage
echo Usage:
echo   build.bat          Generate %OUTPUT_FILE_NAME%
echo   build.bat /clean   Remove build artifacts and virtual environments
popd >nul
exit /b 0

:clean
echo [INFO] Cleaning build artifacts...
call :remove_dir "build"
if errorlevel 1 goto :clean_error
call :remove_dir "dist"
if errorlevel 1 goto :clean_error
call :remove_dir ".venv"
if errorlevel 1 goto :clean_error
call :remove_dir ".venv-win"
if errorlevel 1 goto :clean_error
call :remove_dir ".venv-linux"
if errorlevel 1 goto :clean_error

for /d /r . %%d in (__pycache__) do (
    if exist "%%d" (
        echo [INFO] Removing %%d
        rmdir /q /s "%%d"
        if errorlevel 1 goto :clean_error
    )
)

for %%f in (*.spec) do (
    if exist "%%f" (
        echo [INFO] Removing %%f
        del /q "%%f"
        if errorlevel 1 goto :clean_error
    )
)

echo [INFO] Clean completed.
popd >nul
exit /b 0

:remove_dir
if exist "%~1" (
    echo [INFO] Removing %~1
    rmdir /q /s "%~1"
    if errorlevel 1 exit /b 1
)
exit /b 0

:clean_error
echo [ERROR] Clean failed.
popd >nul
exit /b 1

:error
echo [ERROR] Failed to generate %OUTPUT_FILE_NAME%.
deactivate
popd >nul
exit /b 1
