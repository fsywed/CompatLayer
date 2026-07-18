@echo off
REM ============================================================
REM build_all.bat - ±àÒëËùÓÐ Win7 ÑéÖ¤ÓÃÀý
REM
REM Êä³ö£ºbin\*.exe£¨º¬ win7bridge.dll, win7bridge_loader.exe, pe_patch.exe£©
REM ============================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BIN=%ROOT%bin
set INC=%ROOT%..\..\include
set SRC=%ROOT%..\..\src

if not exist "%BIN%" mkdir "%BIN%"

REM ¼ì²â gcc ÊÇ·ñ¿ÉÓÃ
where gcc >nul 2>&1
if errorlevel 1 (
    echo [FAIL] gcc not found in PATH
    exit /b 127
)

set GCC=gcc
set CFLAGS=-Wall -Wextra -O2 -std=gnu11 -I%INC% -I%ROOT%

REM ============================================================
REM 1. ±àÒë win7bridge.dll£¨¼æÈÝ²ã£©
REM ============================================================
echo [build] win7bridge.dll
set DLL_OBJS=
for /R "%SRC%" %%F in (*.c) do (
    set OBJ=%BIN%\%%~nF.o
    %GCC% %CFLAGS% -D_WIN32 -c "%%F" -o "!OBJ!" 2>build_dll_err.txt
    if errorlevel 1 (
        echo   [FAIL] %%F
        type build_dll_err.txt
    ) else (
        set DLL_OBJS=!DLL_OBJS! "!OBJ!"
    )
)
del build_dll_err.txt 2>nul

%GCC% -shared -o "%BIN%\win7bridge.dll" %DLL_OBJS% -lkernel32 -lbcrypt 2>build_dll_link.txt
if errorlevel 1 (
    echo   [FAIL] link win7bridge.dll
    type build_dll_link.txt
) else (
    echo   [OK]   win7bridge.dll
)
del build_dll_link.txt 2>nul

REM ============================================================
REM 2. ±àÒë win7bridge_loader.exe
REM ============================================================
echo [build] win7bridge_loader.exe
%GCC% %CFLAGS% -D_WIN32 ^
    "%SRC%\loader\loader.c" "%SRC%\loader\inject.c" ^
    -o "%BIN%\win7bridge_loader.exe" -lkernel32 2>build_loader_err.txt
if errorlevel 1 (
    echo   [FAIL] win7bridge_loader.exe
    type build_loader_err.txt
) else (
    echo   [OK]   win7bridge_loader.exe
)
del build_loader_err.txt 2>nul

REM ============================================================
REM 3. ±àÒë pe_patch.exe
REM ============================================================
echo [build] pe_patch.exe
%GCC% %CFLAGS% -D_WIN32 ^
    "%ROOT%pe_patch_cli.c" "%SRC%\pe\pe.c" ^
    -o "%BIN%\pe_patch.exe" 2>build_patch_err.txt
if errorlevel 1 (
    echo   [FAIL] pe_patch.exe
    type build_patch_err.txt
) else (
    echo   [OK]   pe_patch.exe
)
del build_patch_err.txt 2>nul

REM ============================================================
REM 4. ±àÒëËùÓÐ²âÊÔ EXE
REM ============================================================
set BUILD_FAIL=0

echo [build] test_3_1_4_anti_debug.exe
%GCC% %CFLAGS% -D_WIN32 "%ROOT%test_3_1_4_anti_debug.c" -o "%BIN%\test_3_1_4_anti_debug.exe" 2>nul
if errorlevel 1 ( echo   [FAIL] & set /A BUILD_FAIL+=1 ) else ( echo   [OK] )

echo [build] test_3_2_2_high_subsystem.exe
%GCC% %CFLAGS% -D_WIN32 "%ROOT%test_3_2_2_high_subsystem.c" -o "%BIN%\test_3_2_2_high_subsystem.exe" 2>nul
if errorlevel 1 ( echo   [FAIL] & set /A BUILD_FAIL+=1 ) else ( echo   [OK] )

for %%C in (case_01_high_subsystem case_02_apiset_import case_03_get_proc_address case_04_version_spoof case_05_pseudo_console case_06_wait_on_address case_07_bcrypt_chacha20 case_08_ucrt_check) do (
    echo [build] %%C.exe
    %GCC% %CFLAGS% -D_WIN32 "%ROOT%cases\%%C.c" -o "%BIN%\%%C.exe" 2>nul
    if errorlevel 1 (
        echo   [FAIL] %%C
        set /A BUILD_FAIL+=1
    ) else (
        echo   [OK]   %%C
    )
)

echo.
echo ============================================================
echo build_all done. failed=%BUILD_FAIL%
echo ============================================================
exit /b %BUILD_FAIL%
