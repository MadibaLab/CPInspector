try:
    import Tkinter as tk
    from Tkinter import ttk
    from Tkinter import *
    import tkFont as font
    from Tkinter import messagebox
except ImportError:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import font
    from tkinter import *
    from tkinter import messagebox
from selenium.common.exceptions import WebDriverException 
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.events import EventFiringWebDriver
from selenium.webdriver.support.events import AbstractEventListener
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from subprocess import Popen, PIPE
from shutil import copyfile
from hashlib import md5
from selenium.webdriver.firefox.firefox_profile import (
    FirefoxProfile as BaseFirefoxProfile,
    AddonFormatError
)
import requests
import getpass
from glob import glob
from PIL import Image
import webbrowser

import codecs
import zipfile

import gzip
import os
import logging
import shutil
import json
import subprocess
import random
import datetime
import time
import sqlite3
import six
import urllib
import tarfile
import errno
import win32crypt #https://sourceforge.net/projects/pywin32/

__all__ = ['FirefoxProfile']

user = os.getenv('USER') or os.getenv('LOGNAME') or  os.getenv('USERNAME')

#print (user)

DEBUG = True
import pickle
from subprocess import call
##from Naked.toolshed.shell import muterun_js
import atexit


from selenium.webdriver.firefox.firefox_profile import AddonFormatError

# Add class

#------------------------------
# FirefoxProfile1
#-----------------------------
#source: https://github.com/citp/OpenWPM
class FirefoxProfile1(BaseFirefoxProfile):
    """Hook class for patching bugs in Selenium's FirefoxProfile class"""
    def __init__(self, *args, **kwargs):
        BaseFirefoxProfile.__init__(self, *args, **kwargs)

    def _addon_details(self, addon_path):
        """Selenium 3.4.0 doesn't support loading WebExtensions. See bug:
        https://github.com/SeleniumHQ/selenium/issues/4093. This patch uses
        code from PR: https://github.com/SeleniumHQ/selenium/pull/4790"""
        try:
            return BaseFirefoxProfile._addon_details(self, addon_path)
        except AddonFormatError:
            pass

        # Addon must be a WebExtension, parse details from `manifest.json`
        details = {
            'id': None,
            'unpack': False,
            'name': None,
            'version': None
        }

        def get_namespace_id(doc, url):
            attributes = doc.documentElement.attributes
            namespace = ""
            for i in range(attributes.length):
                if attributes.item(i).value == url:
                    if ":" in attributes.item(i).name:
                        # If the namespace is not the default one remove xlmns:
                        namespace = attributes.item(i).name.split(':')[1] + ":"
                        break
            return namespace

        def get_text(element):
            """Retrieve the text value of a given node"""
            rc = []
            for node in element.childNodes:
                if node.nodeType == node.TEXT_NODE:
                    rc.append(node.data)
            return ''.join(rc).strip()

        if not os.path.exists(addon_path):
            raise IOError('Add-on path does not exist: %s' % addon_path)

        try:
            if zipfile.is_zipfile(addon_path):
                # Bug 944361 - We cannot use 'with' together with zipFile
                # because it will cause an exception thrown in Python 2.6.
                try:
                    compressed_file = zipfile.ZipFile(addon_path, 'r')
                    manifest = compressed_file.read('install.rdf')
                finally:
                    compressed_file.close()
            elif os.path.isdir(addon_path):
                manifest_source = 'manifest.json'
                with open(os.path.join(addon_path, manifest_source), 'r') as f:
                    manifest = f.read()
            else:
                raise IOError("Add-on path is neither an XPI nor a "
                              "directory: %s" % addon_path)
        except (IOError, KeyError) as e:
            raise AddonFormatError(str(e), sys.exc_info()[2])

        doc = json.loads(manifest)

        try:
            details['version'] = doc['version']
            details['name'] = doc['name']
        except KeyError:
            raise AddonFormatError(
                "Add-on manifest.json is missing mandatory fields. "
                "https://developer.mozilla.org/en-US/Add-ons/"
                "WebExtensions/manifest.json")

        try:
            id_ = doc['applications']['gecko']['id']
        except KeyError:
            id_ = "%s@%s" % (doc['name'], doc['version'])
            id_ = ''.join(id_.split())
        finally:
            details["id"] = id_

        return details




#------------------------------
# Load defualt application parameter
#-----------------------------
def load_default_params():
   
    fp = open(os.path.join(os.path.dirname(__file__),
                           'params.json'))
    params = json.load(fp)
    fp.close()

    return params

#------------------------------
# AddEnvironementVariables
#-----------------------------
def AddEnvironementVariables():
    #Add environement variable
    myintvariable = params["SSLKeyLogPath"] +"\sslkeylog.log"
    os.environ['SSLKEYLOGFILE'] = str(myintvariable)
    strauss = int(os.environ.get('STRAUSS', '-1'))
    # NB KeyError <=> strauss = os.environ['STRAUSS']
    debussy = int(os.environ.get('DEBUSSY', '-1'))

#------------------------------
# deletetrafficfiles
#-----------------------------                   
def deletetrafficfiles():
    #delete sslkeylog
    myfile= params["SSLKeyLogPath"] +"\\sslkeylog.log"

    ## If file exists, delete it ##
    if os.path.isfile(myfile):
        os.remove(myfile)

    #delete traffic
    myfile= params["SSLKeyLogPath"] +"\\traffic.pcap"

    ## If file exists, delete it ##
    if os.path.isfile(myfile):
        os.remove(myfile)

#------------------------------
# create_driver_session
#-----------------------------
def create_driver_session(session_id, executor_url):
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    # Save the original function, so we can revert our patch
    org_command_execute = RemoteWebDriver.execute

    def new_command_execute(self, command, params=None):
        if command == "newSession":
            # Mock the response
            return {'success': 0, 'value': None, 'sessionId': session_id}
        else:
            return org_command_execute(self, command, params)

    # Patch the function before creating the driver object
    RemoteWebDriver.execute = new_command_execute
    if params["browsertype"] =="Firefox":
        new_driver = webdriver.Remote(command_executor=executor_url, keep_alive=True, desired_capabilities={'acceptInsecureCerts': True, 'browserName': 'firefox', 'marionette': True})
    else:
        new_driver = webdriver.Remote(command_executor=executor_url, keep_alive=True, desired_capabilities={'acceptInsecureCerts': True, 'browserName': 'chrome', 'marionette': True})
        
    new_driver.session_id = session_id

    # Replace the patched function with original function
    RemoteWebDriver.execute = org_command_execute

    return new_driver



#------------------------------
# GetProfilePath
#-----------------------------
# description:
# this is a workaround for strange behavior of selenium
# extract firefox tem profile folder from log file
#-----------------------------
def GetProfilePath(file_path):

    
    #open the log file
    with open(file_path, encoding="utf8") as f:
        for line in f:
            #search for the ine that has "-marionette"  and "rust_mozprofile" to extract the ID
            if "-marionette"  in line:
                if "rust_mozprofile" in line:                   
                    tmpprofile_path = line.partition("rust_mozprofile")[-1].strip()

                    profile_name = tmpprofile_path[1:-1]

    #copy the temp folder path and return it
    profile_path = r"C:\Users\%s\AppData\Local\Temp\rust_mozprofile.%s" %( user ,profile_name)
    
    return profile_path


#------------------------------
# killprocess
#-----------------------------
# description:
# manually kill processes to make sure the test is correct
#-----------------------------
def killprocess():
    #kill processes 

    browserExe = "tshark.exe"
    os.system("taskkill /f /im "+browserExe)

    browserExe = "firefox.exe"
    os.system("taskkill /f /im "+browserExe)

    #todo check the case of jewish hospital
    browserExe = "iexplore.exe"
    os.system("taskkill /f /im "+browserExe)

    browserExe = "MicrosoftEdge.exe"
    os.system("taskkill /f /im "+browserExe)
    
    browserExe = "chrome.exe" 
    os.system("taskkill /f /im "+browserExe)

    browserExe = "wireshark.exe"
    os.system("taskkill /f /im "+browserExe)

    browserExe = "geckodriver.exe" 
    os.system("taskkill /f /im "+browserExe)

    browserExe = "chromedriver.exe"
    os.system("taskkill /f /im "+browserExe)


def getProfilePath( type,browsertype):
    #profile name
    if browsertype =="Firefox":
        profile_name= "Firefox_Profile"
    else:
        profile_name= "Chrome_Profile"

   #get profile path   
    if type =='None':
        original_profile_path = os.path.join(params["root_dir"], "profiles", profile_name)
    elif type =='Ghostery': #ghostery
        original_profile_path =  os.path.join(params["root_dir"] , "profiles","ghostery_" + profile_name)
    elif type =='AdBlock Plus': #Adblockplus 3.2
        original_profile_path =  os.path.join(params["root_dir"] , "profiles","adblockplus_" + profile_name)
    elif type =='Privacy Badger': #Privacy Badger 2018.8.22
        original_profile_path =  os.path.join(params["root_dir"] , "profiles","privacybadger_" + profile_name)
        #original_profile_path = os.path.join(params["root_dir"], "profiles", profile_name)
    elif type =='Incognito': #Incognito
        original_profile_path =  os.path.join(params["root_dir"] , "profiles","Incognito_" + profile_name)

    #copy profile content to the temp profile directory at C:/Users/%s/AppData/Local/Temp/
    #This is applied only for chrome    
    if browsertype != "Firefox":
        if type =='None':
            temp_FP_Path = "C:/Users/%s/AppData/Local/Temp/%s%s" %( user ,profile_name,datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        elif type =='Ghostery': #ghostery
            temp_FP_Path = "C:/Users/%s/AppData/Local/Temp/%s%s" %( user ,"ghostery_" + profile_name,datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        elif type =='AdBlock Plus': #Adblockplus 3.2
            temp_FP_Path = "C:/Users/%s/AppData/Local/Temp/%s%s" %( user ,"adblockplus_" + profile_name,datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        elif type =='Privacy Badger': #Privacy Badger 2018.8.22
            temp_FP_Path = "C:/Users/%s/AppData/Local/Temp/%s%s" %( user ,"privacybadger_" + profile_name,datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

        elif type =='Incognito':
            temp_FP_Path = "C:/Users/%s/AppData/Local/Temp/%s%s" %( user ,"Incognito_" + profile_name,datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        params["browser_profile_path"] = temp_FP_Path 
        shutil.copytree(original_profile_path,params["browser_profile_path"]   ,ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))


    return original_profile_path

#------------------------------
# initiateWebDriver
#-----------------------------
def initiateWebDriver(type,browsertype):
    
    #try: #todo return

        if browsertype =="Firefox":
            #get profile path
            FP = getProfilePath(type,browsertype)
            #print (FP)
            profile= FirefoxProfile1(FP)
            #define binary location path
            binary = FirefoxBinary(params["root_dir"] + r'\browsers\Mozilla Firefox\firefox.exe')
            #set profile preferences
            profile.set_preference("network.http.spdy.enabled.http2", False)
            profile.set_preference("xpinstall.signatures.required", False)
            profile.set_preference("xpinstall.whitelist.required", False)
            profile.set_preference("devtools.netmonitor.persistlog", True)
            if type =='Incognito':
                options = Options()
                profile.set_preference("browser.privatebrowsing.autostart", True)
                profile.set_preference("privacy.trackingprotection.enabled",True)
                options.add_argument('-private')
                
            #add hotspot extension    
            ext_loc = params["root_dir"] + r'\extensions\firefox_extensions\hotspot\hotspot.xpi' 
            ext_loc = os.path.normpath(ext_loc)
            profile.add_extension(extension=ext_loc) 
            

            profile.update_preferences()
            #put driver path in environment variables
            os.environ["PATH"] += os.pathsep +  params["root_dir"] + "\drivers\geckodriver.exe"
            executable_path = params["root_dir"] + "\drivers\geckodriver.exe"
            if type =='Incognito':
                driver =webdriver.Firefox(firefox_binary=binary,firefox_profile=profile,firefox_options=options,  executable_path=executable_path)
            else:
                driver =webdriver.Firefox(firefox_binary=binary,firefox_profile=profile,  executable_path=executable_path)

            #store log file in parameters, form this file we extract temp profile name
            params["driverlogpath"] =  params["output_directory"]   + "\geckodriver.log"

            #read firefox profile path
            params["browser_profile_path"] = GetProfilePath(params["driverlogpath"] )

            #print (params["browser_profile_path"])
        else:
            
            #get profile path
            FP = getProfilePath(type,browsertype)

            #set profile preferences
            options = webdriver.ChromeOptions()
            options.add_argument("user-data-dir=" + params["browser_profile_path"] ) #Path to your chrome profile
            options.add_argument("--disable-http2") 
            options.add_argument("start-maximized")
            options.add_argument("--remote-debugging-port=9222") #source:http://www.assertselenium.com/java/list-of-chrome-driver-command-line-arguments/
            #add extensions 
            if type =='Ghostery':
               options.add_extension(params["root_dir"] + "/extensions/chrome_extensions/Ghostery_v8.2.3.crx")
            elif type=="Privacy Badger":
                 options.add_extension(params["root_dir"] + "/extensions/chrome_extensions/Privacy-Badger_v2018.8.22.crx")
            elif type=="AdBlock Plus":
                 options.add_extension(params["root_dir"] + "/extensions/chrome_extensions/Adblock-Plus_v3.2.crx")
            elif type=="Incognito":
                options.add_argument("--incognito")
            options.add_extension(params["root_dir"] + "/extensions/chrome_extensions/DFPM_v1.15.crx")
            options.add_extension(params["root_dir"] + "/extensions/chrome_extensions/hotspot.crx")
            #define binary location path
            options.binary_location = params["root_dir"] + r'\browsers\Chrome\Application\Chrome.exe'
            #put driver path in environment variables
            executable_path = os.path.join(params["root_dir"] , "drivers","chromedriver.exe")
            os.environ["PATH"] += executable_path

            driver = webdriver.Chrome(executable_path=executable_path, chrome_options=options)#,desired_capabilities=desired)
           
        #save session variables
        params["executor_url"] = driver.command_executor._url
        params["session_id"] = driver.session_id

        #Open browser on url to detect captive portal
        if browsertype =="Firefox":
            driver.get(params["firefox_load"])
            #this code will work only on firefox
            try:
                driver.manage().window().maximize() #maximize the window
            except Exception as e:
                print("")
        else:
    ##        #driver.get("https://mcd-e.datavalet.io/E4358CA832CB4C96A2BCB1C546DF64B7/FC0BEDA4DB49483BADEA173EBE1E0FD0/bG9naW5fdXJsPWh0dHBzJTNBJTJGJTJGbjgxLm5ldHdvcmstYXV0aC5jb20lMkZzcGxhc2glMkZsb2dpbiUzRm1hdXRoJTNETU11Vmt2R0JacGNFY1dDV1hkTzVxZXBGWGNkSDVaOS1JYzhGc2xEZDAwU04tamlSSjlkeHR1OERMd1lhRnQwT1hJQWRmOTFfYzhaallQa3lmYUY5RHg2b0dZUkVhWUh5a1FBeVROS2I1R0x1bW5jdk5RRExNdmlBS0lOa3psNUdWV2x2SktMdzJDbW1yZmRDUFliYm1ac29PZTBGaFIwWlJNLUkzSk9PcEFmek1Ud09ZQWlpaDBLMUx6RXg0aFFBSUk0cWkyZzdKVUhIQSUyNmNvbnRpbnVlX3VybCUzRGh0dHAlMjUzQSUyNTJGJTI1MkZ3d3cubWNkb25hbGRzLmNhJTI1MkYmY29udGludWVfdXJsPWh0dHAlM0ElMkYlMkZ3d3cubWNkb25hbGRzLmNhJTJGJmFwX21hYz04OCUzQTE1JTNBNDQlM0FhYSUzQTkxJTNBMDUmYXBfbmFtZT1NQ0QtUUMtTEFTLTAyMzc5LVdBUDEmYXBfdGFncz0mY2xpZW50X21hYz0wMiUzQWUwJTNBZTMlM0FmMiUzQTUyJTNBYWYmY2xpZW50X2lwPTE5Mi4xNjguMjU1LjE3NA==/fr/welcome.html")
            driver.get(params["chrome_load"])
            #driver.get("https://walmart.ca")

        time.sleep( 20 )
        #save first page open in the browser as Captive portal welcome page
        params["WelcomePageURL"] = driver.current_url

       #add record to sitevisit table
        add_new_page(driver)

        #check if any cookies are written before user approval
        dump_profile_cookies('first')

        #extract source code for the page
        dump_page_source(driver)

        #extract source code for the sub pages
        recursive_dump_page_source (driver,'first')

       # dump local storage
        dump_profile_LocalStorage(driver,'first')

        #capture screen shot
        capture_screenshot(driver)

        #extract all links to url, js, and iframe from page
        extract_js(driver)
        extract_iframe(driver)
        extract_links(driver)


#    except Exception as e:
##        print(e)
##        print ('step: error while open browser, make sure to copy firefox/chrome browsers into c:\hotspot\browser')
##        params["criticalerror"] = True
##        print(e)


  
 
    

    
#------------------------------
# Create_outputfolders
#-----------------------------
def Create_outputfolders():
    # create main directory
    directory = "crawl_output"
    os.chdir('c:\\')
    if not os.path.exists(directory):
      os.makedirs(directory)
    # create current crawl main directory
    os.chdir('c:\\crawl_output')

 
    # create current  output directory for test case

    #remove special char
    name = name_text.get()
    #for k in name.split("\n"):
    name = re.sub(r"[^a-zA-Z0-9]+", ' ', name)
    
    if params["browsertype"] =="Firefox":
        directory = os.path.join(os.getcwd(),  name + "_FF_result" +  datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    else:    
        directory = os.path.join(os.getcwd(),  name + "_C_result" +  datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

    if not os.path.exists(directory):
      os.makedirs(directory)

    params["output_directory"] = directory
   

   # sets up the crawl database
    db_path = params['database_name']
    params["sqlite_address"]= db_path
    db = sqlite3.connect(os.path.join(directory,db_path))
    with open(os.path.join(os.path.dirname(__file__),'schema.sql'), 'r') as f:
            db.executescript(f.read())
    db.commit()
    
    os.chdir(params["output_directory"])
    #define the output directory of browser profile
    browser_profile = os.path.join(os.getcwd(), "Browser_Profile" )
    params["output_browser_profile"] = browser_profile


    if params["browsertype"] !="Firefox":
        #initialize DFPM extension from command line, this will create DFPM.txt file in the output folder
        dump_DFPM()

 
#------------------------------
# find_Wireless_Interface
#-----------------------------
def find_Wireless_Interface():
    interface = "-1"
    ethernet = "-1" #for VM
    wifi     = "-1" #for Windows 10
    args  = ["tshark", "-D"]
    p = subprocess.Popen(args , stdout=subprocess.PIPE) ## Talk with date command i.e. read data from stdout and stderr. Store this info in tuple ##
    (output, err) = p.communicate() ## Wait for date to terminate. Get return returncode ##
    p_status = p.wait()
    idx = 1
    wireless_adapter = params["wireless_adapter"]
    if output != None:
        output = output.lower()

    for item in output.decode().split('\r\n'):
        item = item.strip()
        if not item:
            continue
        if wireless_adapter.lower() in item:
            interface = str(idx)
            
        if 'wi-fi' in item:
            wifi = str(idx)
            
        if 'ethernet' in item:
            ethernet = str(idx)
        idx = idx + 1    


    if  interface == "-1":
        if wifi != "-1":
            interface = wifi
        elif  ethernet != "-1":
            interface = ethernet
        else:
            raise IOError('No Installed wireless or Ethernet Interface for capturing traffic')

        
    return interface



#------------------------------
# initiateWireshark
#-----------------------------
def initiateWireshark():
    #find Wireless Interfase
    interface = params["interface"]
    os.chdir(params["SSLKeyLogPath"])
    args  = ["tshark", "-i", interface, "-w", "traffic.pcap"]
    tsharkProc = subprocess.Popen(args , bufsize=0, executable="C:\\Program Files\\Wireshark\\tshark.exe")
    #tsharkProc = subprocess.Popen(tsharkCall, bufsize=0, executable="C:\\Program Files\\Wireshark\\dumpcap.exe")
    params["tsharkProc"] = tsharkProc
    os.chdir(params["output_directory"])

    

    
#------------------------------
# validateGUI
#-----------------------------
def validateGUI():
    error_message = ""
    if name_text.get() == "":
       error_message = "Name is required."
    if address_text.get() == "":
       error_message = error_message + "\nAddress is required."
    if dropbrowser.get() =="Select Browser":
        error_message = error_message +  "\nBrowser Type is required."

    if chkAccount.get() !="None":
        if email_text.get() =="":
            error_message = error_message +  "\nSpecify Account Email."

    if params["step"] == "Finish":
        if location.get() == 0:
           error_message = "'Have you authorized the service to track your location?' is required."

    return error_message
       


 
#------------------------------
# add_new_page
#-----------------------------
def add_new_page(driver):
    try:
        params["visit_id"] = params["visit_id"] + 1
        current_url = driver.current_url + str(params["visit_id"])
        current_url = urllib.parse.unquote(current_url)
        
        urlhash = md5(current_url.encode('utf-8')).hexdigest()
        current_url = driver.current_url
        if current_url.endswith("#/"):
            current_url = current_url[len(current_url)-2:]

        if current_url.endswith("#_=_"):
            current_url = current_url[len(current_url)-4:]

        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = conn.cursor()

        cur.execute("select 'x' from crawl where crawl_id=?", (params["crawl_id"]))
        data = cur.fetchone()
        
        if data == None:
            insert_query_string = 'INSERT INTO crawl (crawl_id) VALUES (1)'
            cur.execute(insert_query_string)
    
        cur.execute("select 'x' from site_visits where crawl_id=? and visit_id = ?", (params["crawl_id"],params["visit_id"]))
        data = cur.fetchone()
        if data == None:
            insert_query_string = 'INSERT INTO site_visits (visit_id, crawl_id,site_url,hash_url) VALUES (?, ?,?,?)'
            cur.execute(insert_query_string,  (params["visit_id"],params["crawl_id"], current_url,urlhash))

            insert_query_string = 'INSERT INTO links_found (crawl_id,visit_id,found_on, location,type) VALUES (?,?,?, ?,?)'
            cur.execute(insert_query_string, (params["crawl_id"],params["visit_id"],current_url,current_url,'html'))


        conn.commit()
        conn.close()
    except:
        print ("Error Creating new page")
    
#------------------------------
# dump_all_data
#-----------------------------
def dump_all_data():

    time.sleep( 20 )
    
    #initialized driver from session
    driver2 = create_driver_session(params["session_id"], params["executor_url"])
    #todo suzan check if this works in angrinon
    #driver2.switch_to_alert().accept()
    #add visited url to database
    add_new_page(driver2)

    #extract source code for the page
    dump_page_source (driver2)

    #extract source code for the sub pages
    recursive_dump_page_source (driver2,'last')

    #capture screen shot
    capture_screenshot(driver2)

    # dump local storage
    dump_profile_LocalStorage(driver2,'last')

    #extract all links to url, js, and iframe from page
    extract_js(driver2)
    extract_iframe(driver2)
    extract_links(driver2)


#------------------------------
# dump_browser_profile
#-----------------------------
def dump_browser_profile():

    # archive profile folder
    if params["browsertype"] =="Firefox":
      try:
        shutil.copytree(os.path.normpath(params["browser_profile_path"]),os.path.normpath(params["output_browser_profile"]) ,ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))
      except OSError as exc: # python >2.5
       print("")
    else:
      try:
        shutil.copytree(os.path.normpath(params["browser_profile_path"] + "\\Default"),os.path.normpath(params["output_browser_profile"]) ,ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))
      except OSError as exc: # python >2.5
       print("")
        
#------------------------------
# save_hotspot_params
#-----------------------------
def save_hotspot_params(url,file_name):
    try:
        
       # save output  jason file
        hotspot_params ={}
        hotspot_params["hotspotName"] = name_text.get()
        hotspot_params["CrawlDate"] =  datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        hotspot_params["address"] = address_text.get()
        
        hotspot_params["LandingPageUrl"] = url
        hotspot_params["WelcomePageURL"]  = params["WelcomePageURL"]
        hotspot_params["Browsertype"] = params["browsertype"]

        hotspot_params["ProtectionMethod"] = dropProtectionMethod.get()

        hotspot_params["UsedAccount"] = chkAccount.get()
        hotspot_params["account_email"] = email_text.get()
        hotspot_params["ISP"] = ISP_text.get()
        hotspot_params["website"] = website_text.get()


        
        hotspot_params["Critical_Error"] =  params["criticalerror"]

        if 'Upload_Polisis'  in params:
            hotspot_params["Upload_Polisis"]  = params["Upload_Polisis"] 

        hotspot_params["comments"] = text_comments.get("1.0",END)


        if location.get() == 1:
            hotspot_params["geoloc_permission"] =  "Yes"
        else:
            hotspot_params["geoloc_permission"] =  "No"
            

        hotspot_params["hotspot_extension_version"] = "mninphaapoicnaemiigoaillnphomjcb"
        
        with open(file_name + '.json', 'w') as outfile:
            json.dump(hotspot_params, outfile)
    except Exception as e:
        print(e)
        print ("critical: hotspot parameteres are not saved")
        params["criticalerror"]  = True

        
#------------------------------
# copytrfficfilestooutput
#-----------------------------
def copytrfficfilestooutput(type):
    label5.configure(text="Output File Path:", style="BW.TLabel",width=15, justify=LEFT)
    label6.configure(text=params["output_directory"])

    copyfile( params["SSLKeyLogPath"] +"\\sslkeylog.log",params["output_directory"] +"\\sslkeylog.log")


    copyfile( params["SSLKeyLogPath"] +"\\traffic.pcap",params["output_directory"] +"\\traffic.pcap")


#------------------------------
# getdeviceproperties
#-----------------------------
def getdeviceproperties():

    try:
        from win32api import GetSystemMetrics

        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = conn.cursor()
        insert_query_string = 'INSERT INTO device_config (crawl_id,visit_id,key, value) VALUES (?,?,?, ?)'
        for x in range(0, 100):
            cur.execute(insert_query_string, (params["crawl_id"],params["visit_id"],x,GetSystemMetrics(x)))
            
        conn.commit()
        conn.close()
    except:
        print ("")

#------------------------------
# dump_all_final_data
#-----------------------------
def dump_all_final_data():

    time.sleep( 20 )

    #initialized driver from session
    driver2 = create_driver_session(params["session_id"], params["executor_url"])

    #add visited url to database
    add_new_page(driver2)

    #dump browser profile
    dump_browser_profile()

    
    #save hotspot parameters
    params["landingpage"] = driver2.current_url
 
    # dump profile cookies from sqlite database.
    # this step is important for chrome, because we are decrypting  the cookie encrypted values
    dump_profile_cookies('last')


    #extract source code for the sub pages
    recursive_dump_page_source (driver2,'last')
   
    #extract source code for the page
    dump_page_source (driver2)

    #capture screen shot
    capture_screenshot(driver2)

    # dump local storage
    dump_profile_LocalStorage(driver2,'last')


    #save finigerprinting to db
    dump_DFPM_to_db()


    #extract all links to url, js, and iframe from page
    extract_js(driver2)
    extract_links(driver2)
    extract_iframe(driver2)

    #dump params.json file  
    save_hotspot_params(params["landingpage"],"temp_params")


    #kill webdriver
    kill_webdriver(driver2)


    # dump the source code for all the collected url, js, and iframe
    dump_source_code()

    # read device configuration
    getdeviceproperties()

#---------------------------
# dump_profile_cookies
#---------------------------
def dump_profile_cookies (stage):
    if params["browsertype"] =="Firefox":
       dump_firefox_profile_cookies(stage)
    else:
       dump_Chrome_profile_cookies(stage)


#---------------------------
# Command Manager
#---------------------------
def Command_Manager():
    #reset error message
    error.configure(text="")
    #validate GUI
    error_message = validateGUI()
    #if no error  
    if error_message !="":
        error.configure(text=error_message)

    elif params["step"] == "Prepare":
        #ask user to spoof MAC Address
        res = messagebox.askquestion("Spoof MAC Address", "Did you spoof the MAC Address for your 'Wireless Network Connection'?\n\nYou can spoof the MAC address using the TMAC tool.\nIt is available for download from 'https://technitium.com/tmac/'")

        if res == 'yes':
            b1_text.set("Start Registration")
            params["step"] = "Start"
            params["browsertype"] = dropbrowser.get()

            #initialize the user help  fields      
            label1.configure(text="Captive Portal - Important Guidelines:")
            label2.configure(text="1. Select you desired WIFI then click 'Start Registration'.\n2. Don't click the 'Start Registration' button until your system prompt to login.\n3. Do not refresh the browser at any case.\n4. Always wait till the website is loaded completely before taking any action.\n5. Close all browsers on your machine/VM (if any) while the application is running.\n6. Disable the anti-virus while the application is running. \n7. We need to capture the fields read from social media accounts, if not shown, please create your own fake account and repeat the test. \n8. Click 'Save Content' for any renderd page into the browser\n9. Repeat data collection incase of any error (i.e loosing connectivitiy with Captive Portal)")
            e1.configure(state="disabled")
            e2.configure(state="disabled")
            list1.configure(state="disabled")
            ProtectionMethodList.configure(state="disabled")

       
    elif params["step"] == "Start":
        messagebox.showinfo("Important Guidelines", "For data integrity, click 'Save Content' for any rendered page into the browser\n")

        b1_text.set("Finish")
        params["step"] = "Finish"


        #reset the user help  fields      
        label1.configure(text="Captive Portal - Important Guidelines:")
        label2.configure(text="1.Connect to the internet using the launched browser then click Finish.\n2. Do not refresh the browser at any case.\n3. Always wait till the website is loaded completely before taking any action.\n4. Close all browsers on your machine/VM (if any) while the application is running.\n5. Repeat data collection incase of any error (i.e loosing connectivitiy with Captive Portal)")
        label4.configure(text="Important: Click 'Save Content' button for any rendered page into the browser.")

        #Kill Processes
        killprocess()
        #Delete SSl Key Log & traffic
        deletetrafficfiles()
        
        #add environement variable
        AddEnvironementVariables()
        #Create output folders
        Create_outputfolders()

        #Start recording Traffic
        initiateWireshark()
        #Open Browser for captive portal
        initiateWebDriver(dropProtectionMethod.get(),params["browsertype"])

        #show 'save content' button
        b2.grid(row=30, column=1)
    elif params["step"] == "Finish":

   
        #Reset the user help  fields      
        label1.configure(text="")
        label2.configure(text="")
        label4.configure(text="")
       
        #if add policy enable
        if params["Add_Policy"]=="True":
            b1_text.set("Add Policy")
            params["step"] = "Addpolicy"
            label1.configure(text="Captive Portal Policy Collection Guidelines:")
            label2.configure(text="The application will try to upload the policy to Polisis website.\nIf that failed for any reason, please save the policy html code to agreement.html in the output folder.\n\nNote: The system will use Firfox browser to upload the policy.")
         
        else:
            #direct the user to verify stage
            b1_text.set("Verify")
            params["step"] = "verify"
            
        #chkAccountlist.configure(state="disabled")
        #location.configure(state="disabled")
        text_comments.configure(state="disabled")
        #e4.configure(state="disabled")
        #hide 'save content' button
        b2.grid_remove() 


        #save screen shot, session storage, local storage, source code
        dump_all_final_data()

        #give wireshark more time to regeter packets before killing the process
        time.sleep( 100 )

        #save ssl key log file to the output folder
        copytrfficfilestooutput(type)    

       #terminate tshark 
        pro = params["tsharkProc"] 
        pro.send_signal(subprocess.signal.SIGTERM)
        
     
    elif params["step"] == "Addpolicy":
        #Reset the user help  fields      
        label1.configure(text="Captive Portal Policy Collection Guidelines:")
        label2.configure(text="The application will try to upload the policy to Polisis website.\n If that failed for any reason, please save the policy html code to agreement.html in the output folder.")
        label4.configure(text="")

        #messagebox.showinfo("Important Guidelines", "The application will try to upload the policy to Polisis website.\n If that failed for any reason, please save the policy html code to agreement.html in the output folder.")

        b1_text.set("Verify")
        params["step"] = "verify"

        #initiate policy process
        add_policy()
        
    elif params["step"] == "verify":
        #Reset the user help  fields      
        label1.configure(text="")
        label2.configure(text="")
        label4.configure(text="")
        try: 
            driver2 = create_driver_session(params["session_id"], params["executor_url"])
            kill_webdriver(driver2)
        except Exception as e:
            print ("")

        if validate():
          #dump params.json file  
          save_hotspot_params(params["landingpage"],"params")
          b1_text.set("Complete")
          params["step"] = "complete"
            
            
    elif params["step"] == "complete":
        #Reset the user help  fields      
        label1.configure(text="")
        label2.configure(text="")
        label4.configure(text="")
        window.quit()
        window.destroy()
        sys.exit()


#------------------------------
# getSize
#-----------------------------
def getSize(filename):
    st = os.path.getsize(filename)/float(1<<10)
    return st


#------------------------------
# validate
#-----------------------------
def validate():

##    if not os.path.exists(os.path.join(params["output_directory"],'agreement.html')):
##           label1.configure(text="Incomplete Dataset")
##           label4.configure(text="'Privacy policy' was not captured, please save the 'Privacy policy' to the output folder as agreement.html  to output folder." )
##           return False
##    elif not os.path.exists(os.path.join(params["output_directory"],'tos.html')):
##           label1.configure(text="Incomplete Dataset")
##           label4.configure(text="'Terms of Service' was not captured, please save the 'Terms of Service' to the output folder as tos.html  to output folder." )
##           return False
    if not os.path.exists(os.path.join(params["output_directory"],'sslkeylog.log')):
           label1.configure(text="Incomplete Dataset")
           label4.configure(text="sslkeylog - Critical Error occured during the data collection, this dataset should be discarded.")
           return False

    elif not os.path.exists(os.path.join(params["output_directory"],'traffic.pcap')):
           label1.configure(text="Incomplete Dataset")
           label4.configure(text="Traffic.pcap - Critical Error occured during the data collection, this dataset should be discarded.")
           return False
    elif getSize(os.path.join(params["output_directory"],'traffic.pcap')) <200:
           label1.configure(text="Incomplete Dataset")
           label4.configure(text="Traffic.pcap size is very small - Critical Error occured during the data collection, this dataset should be discarded.")
           return False
##    elif not os.path.exists(os.path.join(params["output_directory"],'Source Code')):
##           label1.configure(text="Incomplete Dataset")
##           label4.configure(text="Source Code - Critical Error occured during the data collection, this dataset should be discarded.")
##           return False
    elif params["criticalerror"]:
           label1.configure(text="Incomplete Dataset")
           label4.configure(text="session storage or local sotrage or chrome profile cookies,\nCritical Error occured during the data collection, this dataset should be discarded.")
           return False
    elif  params["browsertype"] !="Firefox":
          if os.stat(os.path.join(params["output_directory"],'DFPM.log')).st_size == 0:
              label1.configure(text="Incomplete Dataset")
              label4.configure(text="DFPM, Critical Error occured during the data collection, this dataset should be discarded.")
              return False
    elif  not os.path.exists(os.path.join(params["output_directory"],'Browser_Profile')): 
               label1.configure(text="Incomplete Dataset")
               label4.configure(text="Browser Profile - Critical Error occured during the data collection, this dataset should be discarded.")
               return False
  
    return True


#------------------------------
# kill_webdriver
#-----------------------------
def kill_webdriver(driver):
    try:
        driver.close() 
    except Exception as e:
        print("")

    browserExe = "firefox.exe"
    os.system("taskkill /f /im "+browserExe)
    
    browserExe = "chrome.exe" 
    os.system("taskkill /f /im "+browserExe)

    browserExe = "iexplore.exe" 
    os.system("taskkill /f /im "+browserExe)

    browserExe = "geckodriver.exe" 
    os.system("taskkill /f /im "+browserExe)


    browserExe = "chromedriver.exe" 
    os.system("taskkill /f /im "+browserExe)

#todo why extension does not retreieve cookie. creation

    #delete profile path if not deleted
    myfile= params["browser_profile_path"]

    ## If file exists, delete it ##
    if os.path.isfile(myfile):
        os.remove(myfile)

    
#------------------------------
# capture_screenshot
#-----------------------------
def capture_screenshot( driver):
    try:
        time.sleep(5)
        
        current_url = driver.current_url + str(params["visit_id"])
        current_url = urllib.parse.unquote(current_url)
        urlhash = md5(current_url.encode('utf-8')).hexdigest()
        outname = os.path.join(params["output_directory"],'%s.png' %( urlhash))
        driver.save_screenshot(outname)

        screenshot_full_page(driver,urlhash)

    except Exception as e:
        print(e)
        print ("warning: screen shot is not captured ")


        
#------------------------------
# _stitch_screenshot_parts
#-----------------------------
#source: https://github.com/citp/OpenWPM
def _stitch_screenshot_parts(driver):
    # Read image parts and compute dimensions of output image
    total_height = -1
    max_scroll = -1
    max_width = -1
    images = dict()
    parts = list()
    for f in glob(os.path.join(params["output_directory"],'parts','%i*-part-*.png' % params["visit_id"])):

        # Load image from disk and parse params out of filename
        img_obj = Image.open(f)
        width, height = img_obj.size
        parts.append((f, width, height))
        outname, _, index, curr_scroll = os.path.basename(f).rsplit('-', 3)
        curr_scroll = int(curr_scroll.split('.')[0])
        index = int(index)

        # Update output image size
        if curr_scroll > max_scroll:
            max_scroll = curr_scroll
            total_height = max_scroll + height

        if width > max_width:
            max_width = width

        # Save image parameters
        img = {}
        img['object'] = img_obj
        img['scroll'] = curr_scroll
        images[index] = img

    # Output filename same for all parts, so we can just use last filename
    outname = outname + '.png'
    outname = os.path.join(params["output_directory"], outname)
    output = Image.new('RGB', (max_width, total_height))

    # Compute dimensions for output image
    for i in range(max(images.keys()) + 1):
        img = images[i]
        output.paste(im=img['object'], box=(0, img['scroll']))
        img['object'].close()
    try:
        output.save(outname)
    except SystemError:
        print(
            "BROWSER %i: SystemError while trying to save screenshot %s. \n"
            "Slices of image %s \n Final size %s, %s." %
            (crawl_id, outname, '\n'.join([str(x) for x in parts]),
             max_width, total_height)
        )
        pass

#------------------------------
# execute_script_with_retry
#-----------------------------
#source: https://github.com/seleniumhq/selenium-google-code-issue-archive/issues/7931#issuecomment-192191013
def execute_script_with_retry(driver, script):
    """Execute script, retrying if a WebDriverException is thrown

    See:
    https://github.com/seleniumhq/selenium-google-code-issue-archive/issues/7931#issuecomment-192191013
    """
    try:
        return driver.execute_script(script)
    except WebDriverException:
        return driver.execute_script(script)


#------------------------------
# screenshot_full_page
#-----------------------------
#source: https://github.com/citp/OpenWPM
def screenshot_full_page(driver, suffix=''):

    outdir = os.path.join(params["output_directory"], 'parts')
    if not os.path.isdir(outdir):
        os.mkdir(outdir)
    if suffix != '':
        suffix = '-' + suffix
    urlhash = md5(driver.current_url.encode('utf-8')).hexdigest()
    outname = os.path.join(outdir, '%i-%s%s-part-%%i-%%i.png' %
                           (params["visit_id"], urlhash, suffix))

    try:
        part = 0
        max_height = execute_script_with_retry(
            driver, 'return document.body.scrollHeight;')
        inner_height = execute_script_with_retry(
            driver, 'return window.innerHeight;')
        curr_scrollY = execute_script_with_retry(
            driver, 'return window.scrollY;')
        prev_scrollY = -1
        driver.save_screenshot(outname % (part, curr_scrollY))
        while ((curr_scrollY + inner_height) < max_height and
                curr_scrollY != prev_scrollY):

            # Scroll down to bottom of previous viewport
            try:
                driver.execute_script('window.scrollBy(0, window.innerHeight)')
            except WebDriverException:
                print(
                    "BROWSER %i: WebDriverException while scrolling, "
                    "screenshot may be misaligned!" % crawl_id)
                pass

            # Update control variables
            part += 1
            prev_scrollY = curr_scrollY
            curr_scrollY = execute_script_with_retry(
                driver, 'return window.scrollY;')

            # Save screenshot
            driver.save_screenshot(outname % (part, curr_scrollY))
    except WebDriverException:
        print(
            "BROWSER %i: Exception while taking full page screenshot \n %s" %
            (crawl_id, ''.join(excp)))
        return

    _stitch_screenshot_parts(driver)



#------------------------------
# dump_DFPM_to_db
#-----------------------------
def dump_DFPM_to_db():
    
    file= os.path.join(params["output_directory"],'DFPM.log')
    if  os.path.isfile(file):
 
        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = conn.cursor()
        with open(file,"r") as f:
            for line in f:
                try:
                    output = json.loads(line)
                    
                    for stack in output["stack"]:
                        parsed = urllib.parse.urlparse(output["url"])
                        domain = parsed.hostname
                        if domain == None:
                            domain = output["url"]

                        if 'functionName' not in stack:
                            stack["functionName"] = ""
                            
                        if 'columnNumber' not in stack:
                            stack["columnNumber"] = ""

                        if 'lineNumber' not in stack:
                            stack["lineNumber"] = ""

                        insert_query_string = 'INSERT INTO DFPM_javascript (crawl_id, url,method,symbol,host,level,category,function_name,script_url,script_line,script_col) VALUES (?,?, ? , ? , ?,?,?,?,?,?,?)'
                        cur.execute(insert_query_string, (params["crawl_id"],output["url"], output["method"],output["path"],domain,output["level"],output["category"],stack["functionName"],stack["fileName"],stack["lineNumber"],stack["columnNumber"]))

                except Exception as e:
                    continue
                    
        cur.execute(" delete from DFPM_javascript"
                       " where rowid not in (select min(rowid)"
                       " from DFPM_javascript"
                       " group by level,category,url,method,host,script_url,script_line,script_col);")
             

     
                     
        conn.commit()
        conn.close()
        f.close()

#------------------------------
# dump_DFPM
#-----------------------------
def dump_DFPM( ):

    outname = os.path.join(params["output_directory"],'DFPM.log')
    #sys.stdout = open(outname, 'w')
    jsfile_path = os.path.join(params["root_dir"], 'extensions','chrome_extensions', 'DFPM', "dfpm.js")
    args  = ["node", jsfile_path, ">>", outname]
    p = subprocess.Popen(args , bufsize=0, shell=True, executable="C:\\Windows\\System32\\cmd.exe")


#------------------------------
# dump_page_source
#-----------------------------
def dump_page_source(driver):

    try:
        current_url = driver.current_url + str(params["visit_id"])
        current_url = urllib.parse.unquote(current_url)
        urlhash = md5(current_url.encode('utf-8')).hexdigest()
        outfile = os.path.join(params["output_directory"], "Source Code",'%s.html' % ( urlhash))

        if not os.path.exists(os.path.join(params["output_directory"], "Source Code")):
            os.mkdir(os.path.join(params["output_directory"], "Source Code"))

        with open(outfile, 'wb') as f:
            f.write(driver.page_source.encode('utf8'))
 


    except Exception as e:
        print(e)
        print ("warning: source code is not captured ")




#------------------------------
# dump_firefox_profile_cookies
#-----------------------------

def dump_firefox_profile_cookies(stage):
    conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
    cur = conn.cursor()

    # Cookies
    if stage == 'first': #after execution of first page
        rows = get_cookies(params["browser_profile_path"])
    else:    
        rows = get_cookies(params["output_browser_profile"])
    if rows is not None:
        for row in rows:
            baseDomain = row[0]
            name = row[1]
            cur.execute("select 'x' from firefox_profile_cookies where crawl_id = ? and visit_id = ? and baseDomain=? and name=?", (params['crawl_id'],params["visit_id"],baseDomain,name))
            data = cur.fetchone()
        
            if data == None:
                query = "INSERT INTO firefox_profile_cookies (crawl_id, visit_id, stage, "\
                         "baseDomain, name, value, host, path, expiry, accessed, "\
                         "creationTime, isSecure, isHttpOnly,InbrowserElement,samesite) VALUES "\
                         "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                cur.execute(query,((params['crawl_id'],params["visit_id"],stage) + row))


    # Close connection to db
    conn.commit()
    conn.close()


#------------------------------
# dump_Chrome_profile_cookies
#-----------------------------
def dump_Chrome_profile_cookies(stage):
    try:
 
        # Connect to the Database
        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cursor = conn.cursor()

        # Get the results
        if stage == 'first': #after execution of first page
            rows = get_chrome_cookies(os.path.join(params["browser_profile_path"], 'Default'))
            print(os.path.join(params["browser_profile_path"]))
            print (rows)
        else:    
            rows = get_chrome_cookies(params["output_browser_profile"])

        #print (rows)
        if rows is not None:
            for row in rows:
                # Decrypt the encrypted_value
                host_key = row[0]
                name = row[1]
                value = row[2]
                encrypted_value = row[3]
                #source  https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8') or value or 0
                # Update the cookies with the decrypted value
                # This also makes all session cookies persistent
                cursor.execute("select 'x' from chrome_profile_cookies where crawl_id = ? and visit_id = ? and host_key=? and name=?", (params['crawl_id'],params["visit_id"],host_key,name))
                data = cursor.fetchone()
            
                if data == None:
                    query = "INSERT INTO chrome_profile_cookies (crawl_id, visit_id, stage," \
                             "host_key, name, value, encrypted_value, has_expires, expires_utc, is_persistent, "\
                             "is_secure,is_httponly,last_access_utc,priority,creation_utc,path,firstpartyonly) VALUES "\
                             "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                    cursor.execute(query,((params['crawl_id'],params["visit_id"],stage) + row))
                    cursor.execute('\
                            UPDATE chrome_profile_cookies SET decrypted_value = ?\
                            WHERE host_key = ?\
                            AND name = ?',
                            (decrypted_value, host_key, name));

                

        conn.commit()
        conn.close()


    except Exception as e:
        print(e)
        print ("critical: chrome cookies was not captured ")
        params["criticalerror"] = True


#------------------------------
# extract_iframe
#-----------------------------
def extract_iframe(webdriver):
    try:
        link_urls = result = webdriver.execute_script('''cells = document.querySelectorAll('iframe');
        URLs = [];
        [].forEach.call(cells, function (el) {
            URLs.push(el.src)
        });
        return URLs''')
        
        cnnCrawl = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = cnnCrawl.cursor()

        if len(link_urls) > 0:
            current_url = webdriver.current_url


            insert_query_string = 'INSERT INTO links_found (crawl_id,visit_id,found_on, location,type) VALUES (?,?,?, ?,?)'
            for link in link_urls:
                if link != '':

                    cur.execute(insert_query_string, (params["crawl_id"],params["visit_id"],current_url, link,'iframe'))



        cur.execute(" delete from links_found"
                       " where rowid not in (select min(rowid)"
                       " from links_found"
                       " group by crawl_id,visit_id,found_on,location);")
             

        cnnCrawl.commit()
        cnnCrawl.close()
    except Exception as e:
        print(e)
        print ("warning: extract_iframe was not captured ")



#------------------------------
# dump_source_code
#-----------------------------
def dump_source_code():
    try:
        cnnCrawl = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = cnnCrawl.cursor()

        cur.execute('select distinct type , location   from links_found where hash_url is null')
        link_urls = cur.fetchall()

        for link in link_urls:
                tlink = urllib.parse.unquote(link[1] )
                urlhash = md5(tlink.encode('utf-8')).hexdigest()
                if link[0] == 'javascript':
                    outfile = os.path.join(params["output_directory"], "Source Code","All Source Code",'%s.js' % ( urlhash))
                elif link[0] == 'html':
                    outfile = os.path.join(params["output_directory"], "Source Code","All Source Code",'%s.html' % ( urlhash))
                elif link[0] == 'iframe':
                    outfile = os.path.join(params["output_directory"], "Source Code","All Source Code",'%s_iframe.html' % ( urlhash))

                if not os.path.exists(os.path.join(params["output_directory"],"Source Code", "All Source Code")):
                    os.mkdir(os.path.join(params["output_directory"],"Source Code", "All Source Code"))
                     

                with open(outfile, 'wb') as f:
                    try:
                        page = requests.get(link[1])
                        pagecontent=page.content
                        f.write(pagecontent)
                    except Exception as e:
                          print(e)
                cur.execute("update links_found set hash_url = ? where type = ? and location = ?", (urlhash, link[0], link[1]))



             
        cnnCrawl.commit()
        cnnCrawl.close()
    except Exception as e:
        print(e)
        print ("warning: dump_source_code was not captured ")
        
##    

#------------------------------
# extract_links
#-----------------------------
def extract_links(webdriver):
    try:
        link_urls = result = webdriver.execute_script('''cells = document.querySelectorAll('a');
        URLs = [];
        [].forEach.call(cells, function (el) {
            URLs.push(el.href)
        });
        return URLs''')
        
        cnnCrawl = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = cnnCrawl.cursor()

        if len(link_urls) > 0:
            current_url = webdriver.current_url
            insert_query_string = 'INSERT INTO links_found (crawl_id,visit_id,found_on, location,type) VALUES (?,?,?, ?,?)'
            for link in link_urls:
                if link != '':

                    cur.execute(insert_query_string, (params["crawl_id"],params["visit_id"],current_url,link,'html'))


        # delete repeated records
        cur.execute(" delete from links_found"
                       " where rowid not in (select min(rowid)"
                       " from links_found"
                       " group by crawl_id,visit_id,found_on,location);")
        # delete any inline javascript     
        cur.execute(" delete from links_found"
                       " where location like 'javascript:%'")

        cnnCrawl.commit()
        cnnCrawl.close()
    except Exception as e:
        print ("warning: extract_links was not captured ")

#------------------------------
# extract_js
#-----------------------------
def extract_js(webdriver):
    try:
        link_urls = result = webdriver.execute_script('''cells = document.querySelectorAll('script');
        URLs = [];
        [].forEach.call(cells, function (el) {
            URLs.push(el.src)
        });
        return URLs''')
        
        cnnCrawl = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = cnnCrawl.cursor()

        if len(link_urls) > 0:
            current_url = webdriver.current_url



            insert_query_string = 'INSERT INTO links_found (crawl_id,visit_id,found_on, location,type) VALUES (?,?,?, ?,?)'
            for link in link_urls:
                if link != '':
                    cur.execute(insert_query_string, (params["crawl_id"],params["visit_id"],current_url, link,'javascript'))



        cur.execute(" delete from links_found"
                       " where rowid not in (select min(rowid)"
                       " from links_found"
                       " group by crawl_id,visit_id,found_on,location);")
             

        cnnCrawl.commit()
        cnnCrawl.close()
    except Exception as e:
        print(e)
        print ("warning: extract_js was not captured ")
    #    params["criticalerror"] = True

#------------------------------
# dump_js_cookies
#-----------------------------
def dump_js_cookies(driver, page_url):

    
    cookies = driver.execute_script("return document.cookie;")

    outname = os.path.join(params["output_directory"],'cookies.log')
    with open(outname, 'a') as the_file:
        the_file.write('{"url": "'  + page_url + '" , "cookies" : "' +   cookies + '"}')
    the_file.close()    

  
   
   
#------------------------------
# dump_js_Session_storage
#-----------------------------
    
def dump_js_Session_storage(driver, page_url):
    #todo return
    #try:    
        if driver.current_url.lower() == 'about:blank':
            return

        
        scriptArray="""return Array.apply(0, new Array(sessionStorage.length)).map(function (o, i) { return sessionStorage.key(i) + ':::' + sessionStorage.getItem(sessionStorage.key(i)); })"""
        result = driver.execute_script(scriptArray)
        
        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = conn.cursor()
        
        for item in result:
            
            key, value = item.split(':::', 1)
            #extract domain name
            parsed = urllib.parse.urlparse(page_url)
            domain = parsed.hostname
            if domain == None:
                domain = page_url

            cur.execute("select scope,key,value from js_sessionStorage where scope=? and key=? and visit_id=?", (domain,key,str(params['visit_id'])))
            data = cur.fetchone()
            if data == None:
                 query = "INSERT INTO js_sessionStorage (crawl_id,visit_id, scope, key, value) "
                 query =    query +       "VALUES (" + str(params['crawl_id']) + "," + str(params['visit_id'])  + ",'" + domain+ "','" +key+ "','" +value+ "')"
                 cur.execute(query)


        cur.execute(" delete from js_sessionStorage"
                       " where rowid not in (select min(rowid)"
                       " from js_sessionStorage"
                       " group by visit_id,scope,key);")
             
        # Close connection to db
        conn.commit()
        conn.close()
    #except Exception as e:
    #    print(e)
    #    print ("critical: session storage was not captured ")
    #    params["criticalerror"] = True


   
    #todo repeat h&m ad block type

#todo check persist logs

#------------------------------
# dump_js_local_storage
#-----------------------------

def dump_js_local_storage(driver, page_url,stage):
    try:
        if driver.current_url.lower() == 'about:blank':
            return
       
        scriptArray="""return Array.apply(0, new Array(localStorage.length)).map(function (o, i) { return localStorage.key(i) + ':::' + localStorage.getItem(localStorage.key(i)); })"""
        result = driver.execute_script(scriptArray)
        
        conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
        cur = conn.cursor()
        
        for item in result:
            
            key, value = item.split(':::', 1)
            #extract domain name
            parsed = urllib.parse.urlparse(page_url)
            domain = parsed.hostname
            if domain == None:
                domain = page_url

            cur.execute("select scope,key,value from js_localStorage where scope=? and key=? and visit_id =?", (domain,key,str(params['visit_id'])))
            data = cur.fetchone()
            
            if data == None:
                    
                 query = "INSERT INTO js_localStorage (crawl_id, visit_id, scope, key, value,stage) "
                 query =    query +       "VALUES (" + str(params['crawl_id']) + "," + str(params['visit_id']) + ",'" + domain+ "','" +key+ "','" +value+ "','" + stage  +"')"
                 cur.execute(query)


        cur.execute(" delete from js_localStorage"
                       " where rowid not in (select min(rowid)"
                       " from js_localStorage"
                       " group by visit_id,scope,key,stage);")
             
        # Close connection to db
        conn.commit()
        conn.close()

    except Exception as e:
        print(e)
        print ("critical: local storage was not captured ")
        params["criticalerror"] = True

    

#------------------------------
# dump_profile_LocalStorage
#-----------------------------

def dump_profile_LocalStorage(driver,stage):

    
    if params["browsertype"] =="Firefox":
       dump_firefox_profile_LocalStorage(stage)
    #else:
        #todo check if we need it
       #dump_Chrome_profile_LocalStorage(stage)
       

#------------------------------
# dump_firefox_profile_LocalStorage
#-----------------------------
#Save changes to Firefox's webappsstore.sqlite to database

def dump_firefox_profile_LocalStorage(stage):

    conn = sqlite3.connect(os.path.join(params["output_directory"],params["database_name"]))
    cur = conn.cursor()

    # LocalStorage
    rows = get_localStorage(params["output_browser_profile"])
    if rows is not None:
        for row in rows:
            query = "INSERT INTO profile_localStorage (crawl_id,stage, "
            query =    query +         " scope, key, value) VALUES "
            query =    query +         "(?,?,?,?,?)"
            cur.execute(query, (params['crawl_id'], stage,row[0],row[1],row[2]))

    # Close connection to db
    conn.commit()
    conn.close()

#------------------------------
# get_localStorage
#-----------------------------
def get_localStorage(profile_directory):
    ff_ls_file = os.path.join(profile_directory, 'webappsstore.sqlite')
    if not os.path.isfile(ff_ls_file):
        print("Cannot find localstorage DB %s" % ff_ls_file)
    else:
        conn = sqlite3.connect(ff_ls_file)
        with conn:
            cur = conn.cursor()
            cur.execute('SELECT scope, KEY, value \
                    FROM webappsstore2 ')
            rows =  cur.fetchall()
        return rows


#------------------------------
# get_cookies
#-----------------------------
def get_cookies(profile_directory):
    
    cookie_db = os.path.join(profile_directory, 'cookies.sqlite')
    if not os.path.isfile(cookie_db):
        print("cannot find cookies.sqlite", cookie_db)
    else:
        conn = sqlite3.connect(cookie_db)
        with conn:
            c = conn.cursor()
            c.execute('SELECT baseDomain, name, value, host, path, expiry,\
                lastAccessed, creationTime, isSecure, isHttpOnly ,InbrowserElement, Samesite\
                FROM moz_cookies ')
            rows = c.fetchall()

        return rows

#------------------------------
# get_chrome_cookies
#-----------------------------
def get_chrome_cookies(profile_directory):

    
    cookie_db = os.path.join(profile_directory, 'Cookies')
    if not os.path.isfile(cookie_db):
        print("cannot find cookies", cookie_db)
    else:
        conn = sqlite3.connect(cookie_db)
        with conn:
            c = conn.cursor()
            c.execute('SELECT host_key, name, value, encrypted_value, has_expires, expires_utc, is_persistent, is_secure,is_httponly,last_access_utc,priority,creation_utc,path,firstpartyonly FROM cookies')
            rows = c.fetchall()
        return rows
            



#------------------------------
# recursive_dump_page_source
#-----------------------------
def recursive_dump_page_source(driver,stage):
    """https://github.com/citp/OpenWPM
    Dump a compressed html tree for the current page visit"""
  
    try:
        
        current_url = driver.current_url + str(params["visit_id"])
        current_url = urllib.parse.unquote(current_url)
        urlhash = md5(current_url.encode('utf-8')).hexdigest()
        outfile = os.path.join(params["output_directory"], "Source Code",'%s.json.gz' % (urlhash))

        def collect_source(driver, frame_stack, rv={}):
            is_top_frame = len(frame_stack) == 1

            # Gather frame information
            doc_url = driver.execute_script("return window.document.URL;")
            if is_top_frame:
                page_source = rv
            else:
                page_source = dict()
            page_source['doc_url'] = doc_url
            
            ############this code inserted for Hotspot project
            source = driver.page_source
            dump_js_Session_storage(driver,doc_url)
            dump_js_local_storage(driver,doc_url,stage)
            #dump_js_cookies(driver,doc_url)
            ########################

            
            if type(source) != six.text_type:
                source = six.text_type(source, 'utf-8')
            page_source['source'] = source
            page_source['iframes'] = dict()

            # Store frame info in correct area of return value
            if is_top_frame:
                return
            out_dict = rv['iframes']
            
            for frame in frame_stack[1:-1]:
                out_dict = out_dict[frame.id]['iframes']
            out_dict[frame_stack[-1].id] = page_source
        page_source = dict()
        execute_in_all_frames(driver, collect_source, {'rv': page_source})

        with gzip.GzipFile(outfile, 'wb') as f:
            f.write(json.dumps(page_source).encode('utf-8'))

    except Exception as e:
       print(e)
       print ("warning: recursive_dump_page_source is not captured")
        #params["criticalerror"]  = True






#------------------------------
# execute_in_all_frames
#-----------------------------
# source: https://github.com/citp/OpenWPM
def execute_in_all_frames(driver, func, kwargs={}, frame_stack=['default'],
                          max_depth=5, logger=None, visit_id=-1):
    """https://github.com/citp/OpenWPM
    Recursively apply `func` within each iframe

    When called at each level, `func` will be passed the webdriver instance
    as an argument as well as any named arguments given in `kwargs`. If you
    require a return value from `func` it should be stored in a mutable
    argument. Function returns and positional arguments are not supported.
    `func` should be defined with the following structure:

  def print_and_gather_links(driver, frame_stack,
                             print_prefix='', links=[]):
      elems = driver.find_elements_by_tag_name('a')
      for elem in elems:
          link = elem.get_attribute('href')
          print print_prefix + link
          links.append(link)

    `execute_in_all_frames` should then be called as follows:

  all_links = list()
  execute_in_all_frames(driver, print_and_gather_links,
                        {'prefix': 'Link ', 'links': all_links})
  print "All links on page (including all iframes):"
  print all_links

    Parameters
    ----------
    driver : selenium.webdriver
        A Selenium webdriver instance.
    func : function
        A function handle to apply to the webdriver instance within each frame
    max_depth : int
        Maximum depth to recurse into
    frame_stack : list of selenium.webdriver.remote.webelement.WebElement
        list of parent frame handles (including current frame)
    logger : logger
        logging module's logger
    visit_id : int
        ID of the visit

    """
    # Ensure we start at the top level frame
    if len(frame_stack) == 1:
        driver.switch_to_default_content()

    # Bail if past depth cutoff
    if len(frame_stack) - 1 > max_depth:
        return

    # Execute function in this frame
    func(driver, frame_stack, **kwargs)

    # Grab all iframes in the current frame
    frames = driver.find_elements_by_tag_name('iframe')

    # Recurse through frames
    for frame in frames:
        frame_stack.append(frame)
        try:
            driver.switch_to_frame(frame)
        except Exception as e:
            if logger is not None:
                print("Error while switching to frame %s (visit: %d))" %
                             (str(frame), visit_id))
            continue
        else:
            if logger is not None:
                doc_url = driver.execute_script("return window.document.URL;")
                print("Switched to frame: %s (visit: %d)" %
                                (doc_url, visit_id))
            # Search within child frame
            execute_in_all_frames(driver, func, kwargs, frame_stack, max_depth)
            switch_to_parent_frame(driver, frame_stack)
        finally:
            frame_stack.pop()


#------------------------------
# switch_to_parent_frame
#-----------------------------
# source: https://github.com/citp/OpenWPM
def switch_to_parent_frame(driver, frame_stack):
    """source: https://github.com/citp/OpenWPM
    Switch driver to parent frame

    Selenium doesn't provide a method to switch up to a parent frame.
    Any frame handles collected in a parent frame can't be used in the
    child frame, so the only way to switch to a parent frame is to
    switch back to the top-level frame and then switch back down to the
    parent through all iframes.

    Parameters
    ----------
    driver : selenium.webdriver
        A Selenium webdriver instance.
    frame_stack : list of selenium.webdriver.remote.webelement.WebElement
        list of parent frame handles (including current frame)
    """
    driver.switch_to_default_content()  # start at top frame
    # First item is 'default', last item is current frame
    for frame in frame_stack[1:-1]:
        driver.switch_to_frame(frame)





#---------------------------
#Start Main function calls
#---------------------------

# load general parameters such as database location
params = load_default_params()
params["interface"] = find_Wireless_Interface()
params["criticalerror"]  = False

params["visit_id"] = 0
params["root_dir"] = params["rootPath"] #os.getcwd()
params["step"] = "Prepare"
params["WelcomePageURL"]  = ""


#---------------------------
#save_agreement
#---------------------------
def save_agreement(driver):
    outname = "agreement"

    outfile = os.path.join(params["output_directory"],'%s.html' % ( outname))

    with open(outfile, 'wb') as f:
        f.write(driver.page_source.encode('utf8'))
        f.write(b'\n')

    params["Upload_Polisis"] = True


#---------------------------
#add_policy
#---------------------------
def add_policy():

   # add policy to polisis

   url = params["WelcomePageURL"]

   params["Upload_Polisis"] = False

   if url != "":
        #use firefox to add policy
        executable_path = params["root_dir"] + r'\browsers\Mozilla Firefox\firefox.exe'
        binary = FirefoxBinary(executable_path)
        executable_path = params["root_dir"] + "\drivers\geckodriver.exe"

        driver =webdriver.Firefox(firefox_binary=binary,executable_path=executable_path)
        try:
            driver.maximize_window() #maximize the
        except Exception as e:
            print("")

        try:
            driver.get("https://pribot.org/polisis")
            time.sleep( 10 )

            #save session variables
            params["executor_url"] = driver.command_executor._url
            params["session_id"] = driver.session_id

             #click not now
            element = WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.XPATH,'/html/body/div/div[4]/div/div/div/div[2]/div/div/button[1]')))
            element.click()

            #add button
            element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH,'//*[@id="policy-search-component"]/div/div[3]/span/span/button')))
            element.click()

            #write company url in the text box
            element_enter  = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH,'/html/body/div/div[2]/div/div/div[2]/div[1]/div[2]/form/div/div[1]/input')))
            element_enter.send_keys(url,Keys.RETURN)

            window_before = driver.window_handles[0]

            ###click download
            element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH,'/html/body/div/div[9]/nav/div/span[2]/span/a')))
            element.click()

            time.sleep( 10 )
            window_after = driver.window_handles[1]
            driver.switch_to_window(window_after)

            #save agreement
            save_agreement(driver)

        except Exception as e:
            print(e)
            label1.configure(text="Incomplete Dataset")
            label4.configure(text="Agreement was not captured, please manually upload it's HTML code as agreement.html  to output folder.\nTo read the agreement, you can click the below button to try to open the captive portal welcome page. " )
            btn_welcome_page.grid(row=32, column=1)




#-----------------------------------
# Create UI
#-----------------------------------

#todo check if the any localstorage written before user contest
window = Tk()
Large_font  = ("Vernada",12)
window.title("CPInspector")
#window.geometry("800x500")
#window.attributes('-fullscreen', True)

w,h = window.winfo_screenwidth() - 300, window.winfo_screenheight() -100
window.geometry("%dx%d+0+0" % (w, h))

helv10 = font.Font(family='Helvetica', size=10)
helv12 = font.Font(family='Helvetica', size=12)
helv16 = font.Font(family='Helvetica', size=16, weight='bold')

style = ttk.Style()
style.theme_use("vista")
style.configure("BW.TLabel", foreground="white", background="blue", font=helv12)

label3 = ttk.Label(window, text="" , font=helv16)
label3.grid(row=0,column=1)


error = ttk.Label(window, text="", font=helv12)
error.grid(row=1,column=1)
error.configure(foreground="red")

#drawl labels

l1 = ttk.Label(window, text="Hotspot Name:" , style="BW.TLabel",width=15, justify=LEFT )
l1.grid(sticky = W,row=2,column=0, padx=5, pady=5)

l1 = ttk.Label(window, text="Hotspot Address:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=3,column=0, padx=5, pady=5)
l1 = ttk.Label(window, text="Browser Type:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=4,column=0, padx=5, pady=5)
if params["DisableSelectBrowser"] == "1":
   l1.grid_remove()

l1 = ttk.Label(window, text="Protection Method:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=5,column=0, padx=5, pady=5)
if params["DisableProtectionMethodList"] == "1":
    l1.grid_remove()


l1 = ttk.Label(window, text="Used Account:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=6,column=0, padx=5, pady=5)

l1 = ttk.Label(window, text="Powered By:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=7,column=0, padx=5, pady=5)

l1 = ttk.Label(window, text="Corporate Website:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = W,row=8,column=0, padx=5, pady=5)


l1 = ttk.Label(window, text="Have you authorized the service to track your location?" , style="BW.TLabel",width=42, justify=LEFT)
l1.grid(sticky = W,row=9,column=0, padx=5, pady=5, columnspan=2)

l1 = ttk.Label(window, text="Comments:" , style="BW.TLabel",width=15, justify=LEFT)
l1.grid(sticky = NW,row=10,column=0, padx=5, pady=5,columnspan=1)




#draw Name field
name_text = StringVar()
e1=Entry(window,textvariable=name_text,width=40)
e1.grid(sticky = W,row=2,column=1)

e1.focus()


address_text = StringVar()
e2=Entry(window,textvariable=address_text,width=50)
e2.grid(sticky = W,row=3,column=1)


#Draw browser drop down
OPTIONS = ["Chrome","Firefox"]
dropbrowser = StringVar(window)
dropbrowser.set(OPTIONS[0]) # default value
list1 = OptionMenu(window, dropbrowser, *OPTIONS)
list1.grid(sticky = W,row=4,column=1)
if params["DisableSelectBrowser"] == "1":
    list1.grid_remove()

#draw drop down
OPTIONS = ["None",  "AdBlock Plus","Privacy Badger","Incognito"]
#OPTIONS = ["None",  "Ghostery","AdBlock Plus","Privacy Badger","Incognito"]
dropProtectionMethod = StringVar(window)
dropProtectionMethod.set(OPTIONS[0]) # default value
ProtectionMethodList= OptionMenu(window, dropProtectionMethod, *OPTIONS)
ProtectionMethodList.grid(sticky = W,row=5,column=1)
if params["DisableProtectionMethodList"] == "1":
    ProtectionMethodList.grid_remove()



#draw drop down
OPTIONS = ["None", "Facebook", "Linkdin","Google", "Twitter", "Instegram" ,"Registration Form", "Others"]
chkAccount = StringVar(window)
chkAccount.set(OPTIONS[0]) # default value
chkAccountlist = OptionMenu(window, chkAccount, *OPTIONS)
chkAccountlist.grid(sticky = W,row=6,column=1)

# on change dropdown value
def change_dropdown(*args):
    if chkAccount.get() == 'None':
        e3.grid_remove()
    else:    
        e3.grid(sticky = E,row=6,column=1, padx=5, pady=5,columnspan=2)
    

# link function to change dropdown
chkAccount.trace('w', change_dropdown)


#draw powered by  field
ISP_text = StringVar()
e4=Entry(window,textvariable=ISP_text,width=40)
e4.grid(sticky = W,row=7,column=1)


#draw corporate website  field
website_text = StringVar()
e5=Entry(window,textvariable=website_text,width=40)
e5.grid(sticky = W,row=8,column=1)


#draw location options
location = IntVar()

Radiobutton(window, text="Yes", variable=location, value=1).grid(row = 9,column=2, padx = 10, pady = 2, sticky=W)

Radiobutton(window, text="No", variable=location, value=2).grid(row = 9,column=3, padx = 10, pady = 2, sticky=W)
#location.grid(sticky = E,row=7,column=1)


text_comments = Text(window, height=7, width=50)
scroll = Scrollbar(window, command=text_comments.yview)

text_comments.configure(yscrollcommand=scroll.set)

text_comments.tag_configure('bold_italics', 
                   font=('Verdana', 12, 'bold', 'italic'))

text_comments.tag_configure('big', 
                   font=('Verdana', 24, 'bold'))
text_comments.tag_configure('color', 
                   foreground='blue', 
                   font=('Tempus Sans ITC', 14))
                   
text_comments.tag_configure('groove', 
                   relief=GROOVE, 
                   borderwidth=2)
                   
text_comments.tag_bind('bite', 
              '<1>', 
              lambda e, t=text_comments: t.insert(END, "Text"))

#text.pack(side=LEFT)
text_comments.grid(sticky = W,row=10,column=1)
#scroll.pack(side=RIGHT, fill=Y)


email_text = StringVar()
e3=Entry(window,textvariable=email_text,width=40)


label0 = ttk.Label(window, text="")
label0.grid(row=10,column=1)

#draw buttons
b1_text = tk.StringVar()
b1=Button(window,textvariable=b1_text,width="14", command=Command_Manager, bg="blue", fg="white")
b1.grid(row=14, column=1)
b1_text.set("Prepare")


l1 = ttk.Label(window, text="")
l1.grid(row=15,column=1)


l1 = ttk.Label(window, text="")
l1.grid(row=29,column=1)

b2_text = tk.StringVar()
b2=Button(window,textvariable=b2_text,width="20", command=dump_all_data, bg="blue", fg="white")
b2.grid(row=30, column=1)
b2_text.set("Save Content")
b2.grid_remove()


label1 = ttk.Label(window, text="")
label1.grid(row=21,column=1)
label1.configure(foreground="red", font=helv12)

label2 = ttk.Label(window, text="", font=helv10)
label2.grid(row=22,column=0,columnspan=4)

label4 = ttk.Label(window, text="", font=helv10)
label4.grid(row=31,column=1,columnspan=4)
label4.configure(foreground="red", font=helv12)


def openweb():
    webbrowser.open(params["WelcomePageURL"])

btn_welcome_page = Button(window, text = "Open Captive Portal Welcome Page",command=openweb, bg="blue", fg="white")

btn_welcome_page.grid(row=32,column=0)
btn_welcome_page.grid_remove()

label3.configure(text="Captive Portal Inspector")

l1 = ttk.Label(window, text="")
l1.grid(row=33,column=0, padx=5, pady=5)

label5 = ttk.Label(window, text="")
label5.grid(row=34,column=0)
label6 = ttk.Label(window, text="", font=helv12)
label6.grid(row=34,column=1, padx=5, pady=5,columnspan=3)


window.mainloop()



#todo update extension to capture value

#todo repeat loto quebec
#todo repeat Cafe Osmo adblock + firefox
#todo alexis Nihon
#check vua sandwitch
#second cup need to be repeated
#todo check Bombay Mahal Chrome Adblock plus _C_result2018-11-17_14-41-14 ok, maybe repeat
#second cup chrome + None need to be repeated

#todo check why h&m did not work with adblock plus
#todo check with for rbc, the welcome page was not loded in chrome 
