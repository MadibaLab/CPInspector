[CmdletBinding()] Param(
    $wiresharkVersion = "2.6.2",
    $wiresharkDownloadPath = "C:\Hotspot\install\tools\wireshark-win64-${wiresharkVersion}.exe",
    $wiresharkInstallDir = "C:\Program files\wireshark"
) 
echo "Install wireshark 2.6.2 to ${wiresharkInstallDir}"
& $wiresharkDownloadPath /S  InstallAllUsers=1 PrependPath=1 Include_test=0 TargetDir=$wiresharkInstallDir

# Set the PATH environment variable for the entire machine (that is, for all users) to include the wireshark install dir


#[Environment]::SetEnvironmentVariable("PATH", "${env:path};${wiresharkInstallDir}", "Machine")


