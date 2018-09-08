Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Python.ps1" 
Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Wireshark.ps1" 



@echo off
echo.
==================================================================
echo   firefox silent install
===================================================================
start C:\hotspot\install\tools\FirefoxSetup60.2.0esr.exe /S /INI=C:\hotspot\Install\tools\firefox.ini 
Echo Done




@echo off
echo.
==================================================================
echo   Chromesilent install
===================================================================

Msiexec /qn /i "C:\hotspot\install\tools\googlechromestandaloneenterprise64.msi" INSTALLDIR="C:\hotspot\browsers"  INSTALLERPATH="<C:\hotspot\install\tools\master_preferences.msp>" 
Echo Done




@echo off
echo.
==================================================================
echo   Wireshark silent install
===================================================================
If not exist C:\Hotspot\Install\Logs\ md C:\Hotspot\Install\Logs\
start /wait C:\Hotspot\Install\tools\Wireshark-win64-2.6.2.exe /S /L*v "C:\Hotspot\Install\logs\wireshrk.log"
Echo Done


@echo off
echo.
==================================================================
echo  winpcab silent install
===================================================================
If not exist C:\Hotspot\Install\Logs\ md C:\Hotspot\Install\Logs\
start /wait C:\Hotspot\Install\tools\WinPcap_4_1_3.exe /S /L*v "C:\Hotspot\Install\logs\winpcap.log"
Echo Done


@echo off
echo.
==================================================================
echo   node js
===================================================================
If not exist C:\Hotspot\Install\Logs\ md C:\Hotspot\Install\Logs\
Msiexec  /i C:\Hotspot\Install\tools\node-v8.11.4-x64.msi  /qn
Echo Done

cd %USERPROFILE%
python -m pip install --upgrade pip
pip install selenium==3.14.0
pip install six
pip install pywin32
cd C:\Hotspot\extensions\chrome_extensions\DFPM
npm install chrome-remote-interface -g
