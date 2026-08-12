@echo off
setlocal
cd /d "%~dp0.."

where cmake >nul 2>&1 || (
  echo CMake 3.23 or later is required.
  exit /b 1
)

cmake --preset windows-x64 || exit /b 1
cmake --build --preset windows-x64-release --parallel || exit /b 1
ctest --test-dir build\windows-x64 -C Release --output-on-failure || exit /b 1

echo Build complete: build\windows-x64\bin\Release\OpenReverse.exe
for %%I in (build\windows-x64\bin\Release\OpenReverse-*-Setup.exe) do echo Installer: %%I
