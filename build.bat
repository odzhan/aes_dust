@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem build.bat [Debug|Release]
rem Builds the aes_dust library and runs tests using CMake.

call :main
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
    echo.
    echo ERROR: Build or tests failed. See messages above.
)
exit /b %RESULT%

:main
set "CONFIG=%~1"
if not defined CONFIG set "CONFIG=Release"

set "BUILD_DIR=build"
set "PROJECT_NAME=AES-dust"

echo === %PROJECT_NAME% build (config=%CONFIG%) ===

call :ensure_tool cmake "Install CMake from https://cmake.org/download/."
if errorlevel 1 exit /b 1

call :detect_ctest

if exist CMakePresets.json (
    call :flow_presets
    exit /b %ERRORLEVEL%
) else (
    echo Presets not found. Using classic CMake workflow.
    call :flow_classic
    exit /b %ERRORLEVEL%
)

:ensure_tool
where %1 >nul 2>&1
if errorlevel 1 (
    echo ERROR: Required tool "%1" not found on PATH.
    if not "%~2"=="" echo        %~2
    exit /b 1
)
exit /b 0

:detect_ctest
where ctest >nul 2>&1
if errorlevel 1 (
    set "HAS_CTEST=0"
    echo NOTE: CTest not detected; tests will be skipped.
) else (
    set "HAS_CTEST=1"
)
exit /b 0

:flow_presets
set "CONFIG_PRESET="
set "BUILD_PRESET="
set "TEST_PRESET="
set "BINARY_DIR="

for %%P in (vs2022) do (
    call :try_configure %%P
    set "RESULT=!errorlevel!"
    if !RESULT! EQU 0 (
        set "CONFIG_PRESET=%%P"
        goto configured
    ) else (
        echo Preset "%%P" failed (exit code !RESULT!). Trying alternatives...
    )
)

if /I "%CONFIG%"=="Debug" (
    set "CONFIG_PRESET=ninja-debug"
    set "BUILD_PRESET=build-debug"
    set "TEST_PRESET=test-debug"
) else (
    set "CONFIG_PRESET=ninja-release"
    set "BUILD_PRESET=build-release"
    set "TEST_PRESET=test-release"
)

call :try_configure %CONFIG_PRESET%
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
    echo Preset "%CONFIG_PRESET%" failed (exit code %RESULT%). Falling back to classic CMake workflow.
    call :flow_classic
    exit /b %ERRORLEVEL%
)

goto configured

:configured
if "%CONFIG_PRESET%"=="vs2022" (
    set "BUILD_PRESET=build-vs2022"
    set "BINARY_DIR=%BUILD_DIR%\vs2022"
) else (
    if not defined BINARY_DIR set "BINARY_DIR=%BUILD_DIR%\%CONFIG_PRESET%"
    if not defined TEST_PRESET (
        for /f "tokens=1* delims=-" %%A in ("%BUILD_PRESET%") do (
            if not "%%B"=="" set "TEST_PRESET=test-%%B"
        )
    )
)

echo [2/3] Building via preset "%BUILD_PRESET%"...
cmake --build --preset %BUILD_PRESET% --parallel
if errorlevel 1 exit /b 1

if "%CONFIG_PRESET%"=="vs2022" (
    call :run_tests preset-vs
) else (
    call :run_tests preset
)
exit /b %ERRORLEVEL%

:flow_classic
set "BINARY_DIR=%BUILD_DIR%"
echo [1/3] Configuring (classic CMake)...
cmake -S . -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=%CONFIG% -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON -DAES_DUST_ENABLE_WERROR=OFF
if errorlevel 1 exit /b 1

echo [2/3] Building (%CONFIG%)...
cmake --build "%BUILD_DIR%" --config %CONFIG% --parallel
if errorlevel 1 exit /b 1

call :run_tests classic
exit /b %ERRORLEVEL%

:try_configure
echo [1/3] Configuring via preset "%~1"...
cmake --preset %~1
exit /b %ERRORLEVEL%

:run_tests
if "%HAS_CTEST%"=="0" (
    echo [3/3] Tests skipped (CTest not available).
    echo === Build finished successfully ===
    exit /b 0
)

echo [3/3] Running tests...
if /I "%~1"=="preset-vs" (
    ctest --test-dir "%BINARY_DIR%" -C %CONFIG% --output-on-failure
) else (
    if /I "%~1"=="preset" (
        ctest --preset %TEST_PRESET% --output-on-failure
    ) else (
        ctest --test-dir "%BUILD_DIR%" -C %CONFIG% --output-on-failure
    )
)
if errorlevel 1 exit /b 1

echo === Build finished successfully ===
exit /b 0
