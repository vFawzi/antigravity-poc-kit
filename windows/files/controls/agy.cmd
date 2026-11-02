@echo off
rem AGY managed launcher (Program Files\Antigravity\bin, first on the machine PATH; admin-only).
rem Human review is mandatory: options that skip it are refused here with a clear message. The corporate hook
rem enforces the same for every launch path (it reads the client's command line), so calling agy.exe directly
rem doesn't help - this shim is the user-facing message, not the control.
setlocal EnableExtensions DisableDelayedExpansion
rem standard users only: not elevated, not a local administrator (the hook denies the same: deny_elevated_session)
net session >nul 2>&1
if not errorlevel 1 (
  echo agy: not permitted in an elevated ^(Run as administrator^) session - start it as a standard user ^(policy^) 1>&2
  eventcreate /L APPLICATION /SO agy-shim /T WARNING /ID 102 /D "BLOCKED user=%USERNAME% reason=elevated_session" >nul 2>&1
  exit /b 126
)
whoami /groups /fo csv /nh 2>nul | findstr /c:"S-1-5-32-544" >nul 2>&1
if not errorlevel 1 (
  echo agy: not permitted for local administrators - use your standard account ^(policy^) 1>&2
  eventcreate /L APPLICATION /SO agy-shim /T WARNING /ID 103 /D "BLOCKED user=%USERNAME% reason=admin_account" >nul 2>&1
  exit /b 126
)
rem capture the arguments before delayed expansion (so "!" in a prompt is kept)
set "AGY_A= %* "
set "AGY_F=%TEMP%\agy-args-%RANDOM%%RANDOM%.txt"
setlocal EnableDelayedExpansion
rem write via redirection (safe for & | < > in prompts); "=" can't be matched with set-substitution, so use findstr
> "!AGY_F!" echo(!AGY_A:"= !
endlocal
findstr /i /r /c:"--dangerously-skip-permissions" /c:"--mode[= ]*auto" /c:"--mode[= ]*accept-edits" "%AGY_F%" >nul 2>&1
set "AGY_RC=%errorlevel%"
del /q "%AGY_F%" >nul 2>&1
if "%AGY_RC%"=="0" (
  echo agy: options that skip human review ^(--dangerously-skip-permissions, --mode auto^|accept-edits^) are not permitted ^(policy^) 1>&2
  eventcreate /L APPLICATION /SO agy-shim /T WARNING /ID 101 /D "BLOCKED user=%USERNAME% reason=review_bypass" >nul 2>&1
  exit /b 126
)
endlocal
"%~dp0..\agy.exe" %*
exit /b %errorlevel%
