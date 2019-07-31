
@echo off
echo.
==================================================================
echo   Add registry variables
===================================================================
powershell -command "Start-Sleep -s 120"
Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Env.ps1" 
Echo Done

