@echo off
set "VS=C:\Program Files\Microsoft Visual Studio\2022\Community"
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS main.c /link /SUBSYSTEM:WINDOWS /OUT:powerfull-ida.exe comdlg32.lib user32.lib gdi32.lib
