# Installation
Currently, Hotspot has primarily been written and tested on windows 7 and windows 10 machines. The following sets of commands should enable it to run on a clean install of Windows10. You can use Oracle VM Virtualbox for this purpose.This vedio (https://www.youtube.com/watch?v=NGJqhSdytWs) can be used as a guidlines for how to install windows 10 on virtual box.




## Installation Instructions


### Step 1: Install Git

First, download and install Git for windows. Use the default settings. It can be downloaded from https://git-scm.com/download/win


### Step 2: Install on Windows using the command line

You can install Hostspot on Windows from the command line with Administrator Privileges.You can always go to the start button and type in "cmd". When the search results are displayed, right click over the command prompt and select the "run as administrator" option. 



#### 1- Open  Command Prompt with Administrator Privileges then run the following command: 


- cd\


- git clone https://github.com/sali123/Hotspot/



- c:\hotspot\install\install.bat 


#### 2- Open  regular Command Prompt (without Administrator Privileges), then run the following command:  

- c:\hotspot\install\installDev.bat 

- Restart the machine (VM if it is used).


### Step3: Running the application

####  Visit any place that has a Public WIFI.


- Open the IDLE program (Windows: Start ? All Programs ? Python 3.7 ? IDLE (Python GUI).

- In the IDLE program, using File ? Open in Windows, go to the c:\hotspot folder. Open the file called "crawl", which might show up as crawl or as crawl.py in the directory listing.


- In the menu, select Run ? Run Module. (The shortcut for this is F5.)


- A screen will open which guide you in the process of connecting to the internet using public WIFI. 