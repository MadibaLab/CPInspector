@echo off
echo.
==================================================================
echo   node js
===================================================================
Msiexec  /i C:\Hotspot\Install\tools\node-v8.11.4-x64.msi  /qn
powershell -command "Start-Sleep -s 300"

Echo Done



@echo off
echo.
==================================================================
echo   Python silent install
===================================================================
start C:\Hotspot\install\tools\python-3.7.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 TargetDir=C:\python37
powershell -command "Start-Sleep -s 120"
Echo Done



@echo off
echo.
==================================================================
echo   Wireshark silent install
===================================================================
Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Wireshark.ps1" 
powershell -command "Start-Sleep -s 120"
Echo Done



@echo off
echo.
==================================================================
echo   firefox silent install
===================================================================
start C:\hotspot\install\tools\FirefoxSetup60.2.0esr.exe /S 
Echo Done




@echo off
echo.
==================================================================
echo   Chrome silent install
===================================================================

Msiexec /i "C:\hotspot\install\tools\googlechromestandaloneenterprise64.msi"  /qn

Echo Done




@echo off
echo.
==================================================================
echo   Wireshark silent install
===================================================================
start /wait C:\Hotspot\Install\tools\Wireshark-win64-2.6.2.exe /S 
Echo Done


@echo off
echo.
==================================================================
echo  winpcab silent install
===================================================================
start /wait C:\Hotspot\Install\tools\WinPcap_4_1_3.exe /S 
Echo Done



@echo off
echo.
==================================================================
echo   Add registry variables
===================================================================
powershell -command "Start-Sleep -s 120"
Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Env.ps1" 
Echo Done

