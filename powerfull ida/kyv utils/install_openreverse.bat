@echo off
title OpenReverse CLI Installer
echo ================================================================================
echo               OPENREVERSE Universal Shell Installer (v2.0)
echo ================================================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_openreverse.ps1"
echo.
pause
