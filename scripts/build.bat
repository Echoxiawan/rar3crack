@echo off
REM build.bat - one-shot local build for Windows (MSVC).
REM Usage: scripts\build.bat [--opencl]
setlocal
cd /d "%~dp0.."

set EXTRA=
if "%1"=="--opencl" set EXTRA=-DRAR3_WITH_OPENCL=ON

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release %EXTRA%
if errorlevel 1 goto :err
cmake --build build --config Release -j
if errorlevel 1 goto :err

echo == running core self-test ==
.\build\Release\selftest.exe
if errorlevel 1 goto :err

echo == done. binary: build\Release\rar3crack.exe ==
exit /b 0

:err
echo build failed
exit /b 1
