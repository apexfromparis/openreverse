@echo off
echo ============================================================
echo    KYV - Memory Analysis ^& Reverse Engineering Tool
echo    Build Script
echo ============================================================
echo.

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
echo [2/3] Building KYV (Release)...
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

if exist bin\Release\KYV.exe (
    echo Executable: bin\Release\KYV.exe
    copy bin\Release\KYV.exe ..\KYV.exe >nul 2>&1
    echo Copied to: KYV.exe (project root)
) else if exist bin\KYV.exe (
    echo Executable: bin\KYV.exe
    copy bin\KYV.exe ..\KYV.exe >nul 2>&1
) else (
    echo Executable location: check build/bin/
)

cd ..
echo.
echo ============================================================
echo    KYV built successfully! Run KYV.exe to launch.
echo ============================================================
pause
