@echo off
REM ============================================================
REM run_all.bat - Win7 verification main entry
REM
REM Single log: results\win7_verify.log (overwritten)
REM Usage: cd scripts\win7_verify && run_all.bat
REM
REM Notes: English-only comments to avoid GBK/UTF-8 codec issues
REM ============================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BIN=%ROOT%bin
set RES=%ROOT%results
set LOG=%RES%\win7_verify.log

if not exist "%RES%" mkdir "%RES%"

REM If bin is missing, run build_all.bat first
if not exist "%BIN%\win7bridge_loader.exe" (
    echo [info] bin missing, running build_all.bat first > "%LOG%"
    call "%ROOT%build_all.bat" >> "%LOG%" 2>&1
)

echo ============================================================ > "%LOG%"
echo Win7Bridge Win7 Verification >> "%LOG%"
echo date: %date% %time% >> "%LOG%"
echo ============================================================ >> "%LOG%"

set PASS_COUNT=0
set FAIL_COUNT=0

REM ============================================================
REM Subroutine: run one test case
REM   %1 = case name (no extension)
REM   %2 = mode: direct | patched_subsystem | loader
REM ============================================================
goto :main

:run_case
set CNAME=%~1
set MODE=%~2
set EXE=%BIN%\%CNAME%.exe
echo. >> "%LOG%"
echo ---- %CNAME% (mode=%MODE%) ---- >> "%LOG%"

if not exist "%EXE%" (
    echo [SKIP] %EXE% not found >> "%LOG%"
    set /A FAIL_COUNT+=1
    goto :eof
)

if "%MODE%"=="patched_subsystem" (
    REM Step 1: pe_patch set subsystem to 10.0 (bad EXE)
    REM Step 2: pe_patch fix subsystem back to 6.1 (good EXE)
    REM Step 3: win7bridge_loader launches the fixed EXE
    "%BIN%\pe_patch.exe" "%EXE%" "%EXE%.bad" --set-subsystem 10.0 >> "%LOG%" 2>&1
    if exist "%EXE%.bad" (
        "%BIN%\pe_patch.exe" "%EXE%.bad" "%EXE%.fixed" --fix-subsystem >> "%LOG%" 2>&1
        if exist "%EXE%.fixed" (
            "%BIN%\win7bridge_loader.exe" --dll "%BIN%\win7bridge.dll" "%EXE%.fixed" >> "%LOG%" 2>&1
            set ERRLVL=!errorlevel!
        ) else (
            echo [FAIL] %EXE%.fixed not generated >> "%LOG%"
            set ERRLVL=999
        )
    ) else (
        echo [FAIL] %EXE%.bad not generated >> "%LOG%"
        set ERRLVL=998
    )
    goto :case_done
)

if "%MODE%"=="loader" (
    "%BIN%\win7bridge_loader.exe" --dll "%BIN%\win7bridge.dll" "%EXE%" >> "%LOG%" 2>&1
    set ERRLVL=!errorlevel!
    goto :case_done
)

REM direct mode: run EXE directly
"%EXE%" >> "%LOG%" 2>&1
set ERRLVL=!errorlevel!

:case_done
echo exit_code=!ERRLVL! >> "%LOG%"
if "!ERRLVL!"=="0" (
    echo RESULT: PASS >> "%LOG%"
    set /A PASS_COUNT+=1
) else (
    echo RESULT: FAIL >> "%LOG%"
    set /A FAIL_COUNT+=1
)
goto :eof

:main
call :run_case test_3_1_4_anti_debug     direct
call :run_case test_3_2_2_high_subsystem patched_subsystem
call :run_case case_01_high_subsystem    patched_subsystem
call :run_case case_02_apiset_import     loader
call :run_case case_03_get_proc_address  loader
call :run_case case_04_version_spoof     loader
call :run_case case_05_pseudo_console    loader
call :run_case case_06_wait_on_address   loader
call :run_case case_07_bcrypt_chacha20   loader
call :run_case case_08_ucrt_check        loader

echo. >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo SUMMARY: PASS=%PASS_COUNT% FAIL=%FAIL_COUNT% >> "%LOG%"
echo ============================================================ >> "%LOG%"

echo.
echo Done. See %LOG%
type "%LOG%" | findstr /R "RESULT SUMMARY"
exit /b %FAIL_COUNT%
