[CmdletBinding()] Param(
    $pythonVersion = "3.7.0",
    $pythonDownloadPath = "C:\Hotspot\install\tools\python-${pythonVersion}-amd64.exe",
    $pythonInstallDir = "C:\python37"
) 
#echo "Install Python 3.7.0 to ${pythonInstallDir}"
#& $pythonDownloadPath /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 TargetDir=$pythonInstallDir

# Set the PATH environment variable for the entire machine (that is, for all users) to include the Python install dir


[Environment]::SetEnvironmentVariable("PATH", "${env:path};%APPDATA%\Roaming\npm;\C:\Program Files\nodejs\;C:\Program files\wireshark;${pythonInstallDir};${pythonInstallDir}\Scripts;${pythonInstallDir}\Lib\site-packages;", "Machine")


#[Environment]::SetEnvironmentVariable("PATH", "${env:path};${pythonInstallDir}\Lib\site-packages", "Machine")

