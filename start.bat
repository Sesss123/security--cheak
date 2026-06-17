@echo off
title Security Platform Launcher
echo ==============================================
echo    SECURITY PLATFORM AUTO-START ENGINE
echo ==============================================
echo Launching startup script in PowerShell...
powershell -ExecutionPolicy Bypass -File .\start-project.ps1
pause
