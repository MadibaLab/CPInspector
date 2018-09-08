Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Python.ps1" 
Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Wireshark.ps1" 



==================================================================
echo   firefox silent install
===================================================================
start C:\hotspot\install\tools\FirefoxSetup60.2.0esr.exe /S /INI=C:\hotspot\Install\tools\firefox.ini 


@echo off
echo.
==================================================================
echo   Wireshark silent install
===================================================================
If not exist C:\Hotspot\Install\Logs\ md C:\Hotspot\Install\Logs\
start /wait C:\Hotspot\Install\tools\WiresharkPortable_2.4.9.paf.exe /S /L*v "C:\Hotspot\Install\logs\WiresharkPortable_2.4.9.paf.log"
Echo Done


@echo off
echo.
==================================================================
echo   node js
===================================================================
If not exist C:\Hotspot\Install\Logs\ md C:\Hotspot\Install\Logs\
start /wait C:\Hotspot\Install\tools\node-v8.11.4-x64.msi /S /L*v "C:\Hotspot\Install\logs\nodejs.log"
Echo Done

python -m pip install --upgrade pip
pip install selenium==3.14.0
pip install six
pip install pywin32
cd C:\Hotspot\extensions\chrome_extensions\DFPM
npm install chrome-remote-interface -g
