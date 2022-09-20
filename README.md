# Yaraedr
Here is our new tool YARA_EDR. Well it’s not a full fledged EDR but it can call at a small part of an EDR to accurately detect malwares executing in your environment. The tool is a wrapper around the yara binary for windows. It relies on the memory scanning capabilities and scans the virtual memory of all the processes on a system to identify malware patterns. The detection is sent to Elastic search server along with information like user name and hostname.  The tool can be used for malware analysis, Threat Hunting, Incident Response. Let’s explore some features of the tool.

Tool can be used in Malware Analysis and Threat Hunting related scenarios. You can write malware signatures in form of yara rules and pass on to the tool.
There are two ways to use the program:

1. Python script<br/>
2. Standalone executable ( packed with Pyinstaller)
  

Usage:                                      

Option1 : Get help options <br />
                                           
python  yaraedr.py -h<br/>
yaraedr64.exe -h
                                          

Option2 : Use elasticsearch to forward logs and use a single yara file<br/>

        
python  yaraedr.py -es y -yf <yara filename><br/>
yaraedr64.exe -es y -yf <yara filename><br/>
                                               
                
                                           
 Option3 : Use elasticsearch to forward logs and use a directory with multiple yara files<br/>
        
python  yaraedr.py -es y -yd <name of directory><br/>
yaraedr64.exe -es y -yd <name of directory><br/>
