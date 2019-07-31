# Installation
Hotspots are physical locations where people can gain free internet access through a Wi-Fi connection.

Currently, CPInspector application has primarily been written and tested on windows 7/8/10 Window machines. 





## Installation Instructions

### Option1: Install the application from VM

1-Download and install Oracle VM VirtualBox.

2-Download the VM from https://drive.google.com/open?id=1Rl1NRhPPNpCZ943Nmf3LchT1ypsunYcs

3- Start VirtualBox,  and select Add from the Machine menu.

4- Select the download hotspot.vbox and select Open.

Unpacking the VM instance and preparing it for use could take a while. 


#### Credentials

-hotspot / hotspot	

### Option 2: Install the application from GitHub

#### Step 1: Download the application

1- Download and install Git for windows. Use the default settings. It can be downloaded from https://git-scm.com/download/win

2- Run git clone https://github.com/MadibaLab/CPInspector 

3- Copy the CPInspector  folder to c:\ and rename it to hotspot

#### Step 2: Install Prerequisites on Windows

Install the following programs on your machine:

1- Python 3.7+ , install  python37 to c:\Program Files\Python37  from C:\hotspot\install\tools\python-3.7.0-amd64.exe

2- Wireshark 2.6.2 +, Install Wireshark from c:\hotspot\install\tools\Wireshark-win64-2.6.2.exe

3- Node JS 8.1.1.4, install Node v8.11.4 from c:\hotspot\install\tools\node-v8.11.4-x64.msi


#### Step 3: Setting  Up PATH
Programs and other executable files can be in many directories, so operating systems provide a search path that lists the directories that the OS searches for executables. Make sure to add the following directories to PATH Environment Variable in Windows (if not added before):

C:\Program Files\nodejs
C:\Program Files\Wireshark
C:\Program Files\python37
C:\Program Files\python37\Scripts
C:\Program Files\python37\Lib\site-packages
C:\users\[user Name]\AppData\Local\Programs\Python\Python37\Scripts
C:\users\[user Name]\AppData\Local\Programs\Python\Python37
C:\users\[user Name]\AppData\Roaming\npm
 
For the latest three variables, please replace [user name] with your windows user name.


### #Installing Dependencies 

Open a Command Prompt, then run the following command:
 
pip install selenium==3.14.0 --user
pip install six  --user
pip install pywin32 --user
pip install lxml --user
cd C:\Hotspot\extensions\chrome_extensions\DFPM
npm i npm
npm -i
npm install chrome-remote-interface
pip install lxml --user
pip install Pillow --user
pip install requests --user


#### Step 4: Configure Wireless Adapter Name

- Open Control Panel.
- Click on Network and Internet.
- Click on Network and Sharing Center
- Click Change Adapter Setting
- Right-click the Wireless network adapter, and then tap or click Rename.
- Set name to HS-Wi-Fi, then click enter. 


#### Step5: Restarting Your Computer


### Running the application

####  Visit any place that has a Public Wi-Fi.


- Open the IDLE program (Windows: Start ? All Programs ? Python 3.7 ? IDLE (Python GUI).

- In the IDLE program, using File ? Open in Windows, go to the c:\hotspot folder. Open the file called "crawl", which might show up as crawl or as crawl.py in the directory listing.


- In the menu, select Run ? Run Module. (The shortcut for this is F5.)


- A screen will open which guide you in the process of connecting to the internet using public WIFI. 

- Enter or select the following information:

	###### Hotspot Name
	Enter the Hotspot Name, use the same name for all datasets.

	###### Hotspot Address
	Enter the Hotspot Address.



- Close all browsers on your machine/VM (if any) while the application is running to avoid capturing invalid traffic.

- Spoof the 'Wireless Network Connection' Mac Address then Click Prepare button.

- Connecting to the desired WiFi from the bottom right corner of your screen.
--you are not granted a full access to the internet, you need further actions to view/accept terms and conditions.
.
-Wait until the captive portal url is fully loaded into the automated browser, then go to the application click "Save Content" button. 

-Go back to the browser to click the "Connect" button.

-Open the browser and go through the  connect to internet wizard taking into consideration the below guidelines:

	 * For data integrity, Click 'Save Content' for any url loaded into the browser other than the 'Welcome page' and 'Landing page' (e.g. Facebook login)
	 * Do not refresh the browser at any case.

	 * Always wait till the page is loaded completely before taking any action.

	 * Repeat data collection incase of any error (i.e loosing connectivitiy with Captive Portal)

-Enter the following information:

	###### Account Used
	Select the account used for connecting to the hotspot (i.e. Faceboox, LinkedIn) or None if no account was used. 


- Click 'Finish' button.

The output folder name is shown in the application.


- Click 'Verify' button. Discard the dataset if it could not be verified sucessfully.


- Click 'Complete' button.



### Notes:
1- Please extract a copy of hotspot Terms of Use and Privacy Policies and save them in the output folder in html format. 
2- Repeat data collection for other all cases if possible, for example (connecting to the hotspot via social media accounts such as Facebook, LinkedIn, etc..). We have already created fake accounts that can be used in the next section.
3- When testing using social media account, please make sure that you are able to see  the fields that are read from the account. If you cannot see these fields that means that the used account has been used before in this hotspot and you need to use another fake account.

###Fake Account
for your own privacy, if required by hotspot, please use the fake accounts in the below link, and not your personal accounts:
 
https://docs.google.com/document/d/1aEqHuW0vcbiwsp-SudD4nkboVM1Pj7sRI9uEs5fpqWU/edit#





