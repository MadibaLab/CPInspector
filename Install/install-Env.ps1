# Set the PATH environment variable for the entire machine (that is, for all users) to include the Python install dir, wireshrak, nodejsm npm


[Environment]::SetEnvironmentVariable("PATH", "${env:path};%APPDATA%\Roaming\npm;C:\Program Files\nodejs;C:\Program Files\Wireshark;C:\Program Files\python37;C:\Program Files\python37\Scripts;C:\Program Files\python37\Lib\site-packages;", "Machine")

#[Environment]::SetEnvironmentVariable("PATH", "${env:path};%APPDATA%\Roaming\npm;C:\Program Files\nodejs;C:\Program Files\Wireshark;", "Machine")


