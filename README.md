# Installation
Hotspots are physical locations where people can gain internet access through a Wi-Fi connection.

Currently, Hotspot application has primarily been written and tested on windows 7 and windows 10 machines. The following sets of commands should enable it to run on a clean install of Windows10. You can use Oracle VM Virtualbox for this purpose.This vedio (https://www.youtube.com/watch?v=NGJqhSdytWs) can be used as a guidlines for how to install windows 10 on virtual box.




## Installation Instructions


### Step 1: Install Git

First, download and install Git for windows. Use the default settings. It can be downloaded from https://git-scm.com/download/win


### Step 2: Install on Windows using the command line

You can install Hostspot on Windows from the command line with Administrator Privileges.You can always go to the start button and type in "cmd". When the search results are displayed, right click over the command prompt and select the "run as administrator" option. 



#### 1- Open  Command Prompt with Administrator Privileges then run the following command: 


- cd\


- git clone https://github.com/sali123/Hotspot/



- c:\hotspot\install\install.bat 

-check if the PATH  system enviroment variable has the following:

%APPDATA%\Roaming\npm;C:\Program Files\nodejs;C:\Program Files\Wireshark;c:\python37;c:\python37\Scripts;c:\python37\Lib\site-packages; 

If not, run Powershell.exe -ExecutionPolicy bypass -File "c:\hotspot\Install\Install-Env.ps1"


#### 2- Open  regular Command Prompt (without Administrator Privileges), then run the following command:  

- c:\hotspot\install\installDev.bat 

- Restart the machine (VM if it is used).


### Step 3: 

Download and install TMAC for windows  from 'https://technitium.com/tmac/. Technitium MAC Address Changer allows you to change (spoof) Media Access Control (MAC) Address of your Network Interface Card (NIC) instantly.


### Step 4: Running the application

####  Visit any place that has a Public WIFI.


- Open the IDLE program (Windows: Start ? All Programs ? Python 3.7 ? IDLE (Python GUI).

- In the IDLE program, using File ? Open in Windows, go to the c:\hotspot folder. Open the file called "crawl", which might show up as crawl or as crawl.py in the directory listing.


- In the menu, select Run ? Run Module. (The shortcut for this is F5.)


- A screen will open which guide you in the process of connecting to the internet using public WIFI. 

- Enter or select the following information:

	###### Hotspot Name
	Enter the Hotspot Name, use the same name for all datasets.

	###### Hotspot Address
	Enter the Hotspot Address.

	###### Browser Type
	Select the browser type (Firefox or Chrome).

	###### Protection Method
	Select the extension that will be used for this purpose (Ghostery, Adblock Plus, Privacy Badger, Incognito) or None if you don't want to use any extension.

	###### Account Used
	Select the account used for connecting to the hotspot (i.e. Faceboox, LinkedIn) or None if no account was used. 


- Close all browsers on your machine/VM (if any) while the application is running to avoid capturing invalid traffic.

- Spoof the 'Wireless Network Connection' Mac Address then Click Prepare button.

- Connecting to the desired WiFi from the bottom right corner of your screen.

- When the windows notified you that you have limited connictivity, and you need further authentication. click Start button.

- The browser will load the captive portal. go through the  connect to the internet wizard taking into consideration the below guidlines:

	 * For data integrity, Click 'Save Content' for any url loaded into the browser other than the 'Welcome page' and 'Landing page' (e.g. Facebook login)
	 * Do not refresh the browser at any case.

	 * Always wait till the page is loaded completely before taking any action.

	 * Repeat data collection incase of any error (i.e loosing connectivitiy with Captive Portal)

- Click 'Finish' button.

- Click 'Add Policy', the application will try to upload the policy to Polisis website. If that failed for any reason, please save the policy html code to agreement.html in the output folder. Note the name of the output folder.

- Click 'Verify' button. Discard the dataset if it could not be verified sucessfully.


- Click 'Complete' button.





