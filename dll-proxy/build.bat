@echo off
echo Building dinput8.dll proxy...

REM Find Visual Studio Build Tools
set "VCVARS="
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

if "%VCVARS%"=="" (
    echo ERROR: Could not find Visual Studio Build Tools!
    echo Install with: winget install Microsoft.VisualStudio.2022.BuildTools
    pause
    exit /b 1
)

call "%VCVARS%"

cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib psapi.lib

if exist dinput8.dll (
    echo.
    echo SUCCESS! dinput8.dll created.
    echo.
    echo Copy dinput8.dll to: D:\Games\FIFA 17\
    echo Then launch FIFA 17 and check fifa17_ssl_bypass.log
) else (
    echo.
    echo BUILD FAILED!
)

pause
