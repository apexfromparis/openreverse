@echo off
echo ============================================================
echo    OpenReverse - Memory Analysis ^& Reverse Engineering Tool
echo    Build Script
echo ============================================================
echo.

cd /d "%~dp0.."

:: Check for CMake
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake not found! Please install CMake 3.20+
    echo Download from: https://cmake.org/download/
    pause
    exit /b 1
)

:: Check for Git (needed by FetchContent)
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git not found! Please install Git.
    echo Download from: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo [1/3] Configuring CMake...
if not exist build mkdir build
cd build

cmake .. -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [INFO] VS 2022 not found, trying VS 2019...
    cmake .. -G "Visual Studio 16 2019" -A x64
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo [INFO] Trying Ninja generator...
        cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release
        if %ERRORLEVEL% NEQ 0 (
            echo.
            echo [ERROR] CMake configuration failed!
            echo Make sure you have Visual Studio 2019/2022 or Ninja installed.
            cd ..
            pause
            exit /b 1
        )
    )
)

echo.
echo [2/3] Building OpenReverse (Release)...
cmake --build . --config Release --parallel
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed!
    cd ..
    pause
    exit /b 1
)

echo.
echo [3/3] Build complete!
echo.

if exist bin\Release\OpenReverse.exe (
    echo Executable: bin\Release\OpenReverse.exe
    copy bin\Release\OpenReverse.exe ..\OpenReverse.exe >nul 2>&1
    echo Copied to: OpenReverse.exe (project root)
) else if exist bin\OpenReverse.exe (
    echo Executable: bin\OpenReverse.exe
    copy bin\OpenReverse.exe ..\OpenReverse.exe >nul 2>&1
) else (
    echo Executable location: check build/bin/
)

cd ..
echo.
echo ============================================================
echo    OpenReverse built successfully! Run OpenReverse.exe to launch.
echo ============================================================
pause
