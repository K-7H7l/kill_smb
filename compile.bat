@echo off
echo Compiling kill_smb.exe ...
cl.exe kill_smb.c /Fe:kill_smb.exe
if %errorlevel% equ 0 (
    echo [+] Compilation successful: kill_smb.exe
) else (
    echo [-] Compilation failed
)
pause
