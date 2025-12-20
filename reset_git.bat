@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Reset Git history so the latest commit is the only commit.
rem This script removes .git, reinitializes the repo, sets identity,
rem adds all files, and creates a single initial commit.

rem --- Configuration (defaults) ---
set NAME=odzhan
set EMAIL=odzhan@protonmail.com
set BRANCH=master
set REMOTE=

rem Allow overrides via env vars GIT_NAME / GIT_EMAIL
if not "%GIT_NAME%"=="" set NAME=%GIT_NAME%
if not "%GIT_EMAIL%"=="" set EMAIL=%GIT_EMAIL%
if not "%GIT_BRANCH%"=="" set BRANCH=%GIT_BRANCH%
if not "%GIT_REMOTE%"=="" set REMOTE=%GIT_REMOTE%

rem Commit message: use all args or default
set "MSG=%*"
if "%~1"=="" set "MSG=Initial commit"
rem Strip any embedded quotes to prevent nested-quote parsing issues
set "MSG=%MSG:"=%"

echo === Resetting Git history in: %CD% ===

where git >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git not found on PATH.
    exit /b 1
)

rem Avoid "dubious ownership" warnings on Windows and also allow reading old config
git config --global --add safe.directory "%CD%" >nul 2>&1

rem Try to capture existing remote before removing .git (if any)
for /f "usebackq delims=" %%R in (`git config --local --get remote.origin.url 2^>nul`) do set OLD_REMOTE=%%R
if "%REMOTE%"=="" if not "%OLD_REMOTE%"=="" set REMOTE=%OLD_REMOTE%

if exist ".git" (
    echo Removing existing .git directory...
    rmdir /S /Q ".git"
    if exist ".git" (
        echo ERROR: Failed to remove .git directory.
        exit /b 1
    )
) else (
    echo No existing .git directory found. Continuing...
)

echo Initializing repository...
git init
if errorlevel 1 goto :err

rem Ensure safe.directory still recorded after re-init
git config --global --add safe.directory "%CD%" >nul 2>&1

echo Configuring author identity...
git config user.name "%NAME%"
if errorlevel 1 goto :err
git config user.email "%EMAIL%"
if errorlevel 1 goto :err

echo Adding files...
git add -A
if errorlevel 1 goto :err

echo Committing...
git commit -m "%MSG%"
if errorlevel 1 goto :err

rem Set desired primary branch name
git branch -M %BRANCH%
if errorlevel 1 goto :err

rem Configure remote (if available via env or captured earlier)
if not "%REMOTE%"=="" goto :push_remote
goto :no_remote

:push_remote
echo Setting remote origin to: %REMOTE%
git remote add origin "%REMOTE%"
if errorlevel 1 goto :err
echo Fetching origin to update remote refs...
git fetch origin --prune
if errorlevel 1 goto :push_failed
echo Pushing %BRANCH% to origin (force-with-lease)...
git push -u origin %BRANCH% --force-with-lease
if errorlevel 1 (
    echo Lease failed or remote changed. Retrying with --force...
    git push -u origin %BRANCH% --force
    if errorlevel 1 goto :push_failed
)
goto :done

:push_failed
echo WARNING: Push failed. Possible causes: no auth, protected branch, or network.
echo Try manually:
echo     git fetch origin --prune
echo     git push -u origin %BRANCH% --force-with-lease
echo If branch protection blocks force-push, temporarily disable it or push to a new branch.
goto :done

:no_remote
echo No remote configured. To push, set env var GIT_REMOTE or run:
echo     git remote add origin ^<url^> ^&^& git push -u origin %BRANCH% --force-with-lease

:done
echo.
echo Done. This repo now has a single commit.
git log --oneline -n 1

exit /b 0

:err
echo.
echo ERROR: A step failed. See messages above.
exit /b 1
