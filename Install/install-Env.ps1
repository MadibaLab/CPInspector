# Set the PATH environment variable for the entire machine (that is, for all users) to include the Python install dir, wireshrak, nodejsm npm


[Environment]::SetEnvironmentVariable("PATH", "${env:path};%APPDATA%\Roaming\npm;C:\Program Files\nodejs;C:\Program Files\Wireshark;c:\python37;c:\python37\Scripts;c:\python37\Lib\site-packages;", "Machine")



