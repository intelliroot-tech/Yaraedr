import subprocess
import wmi
import argparse
import os
from datetime import datetime
from elasticsearch import Elasticsearch
import json
import yara # pip install yara-python
import warnings
warnings.filterwarnings("error")
banner = """
    ---------------------------------------------------
    Yara_Memory_Hunter
    copyright @Intelliroot Technologies
    Author : Abhijit Mohanta
    ---------------------------------------------------
"""
elk_srv = "localhost"
elk_port = 0
elk_index_name = "test"
elk_set = "N"
elk_username = "elastic"
elk_pass = "elastic"

def elk_check():
    global elk_srv
    global elk_port
    global elk_index_name
    global elk_username
    global elk_pass
    global elk_set

    elk_set = 'Y'
    elk_srv = input("Please enter ELK Server Adddress (default:'localhost'):") or 'localhost'
    elk_port = input("Please enter ELK Server port (default:9200):") or 9200
    elk_index_name = input("Please enter index name:") or "test"
    elk_username = input("Please enter username :") or "elastic"
    elk_pass = input("Please enter password:") or "admin"
    try:
        print("[+] Testing elasticsearch db connectivity")
        print("-------------------------------------------")
        print(" ")
        es = Elasticsearch([{'host': elk_srv, 'port': elk_port,'scheme':"https"}],http_auth=(elk_username, elk_pass),verify_certs=False)
        doc = {
            'Client': 'test',
            'ProcessName': 'testp',
            'ProcessOwner': 'testpowner',
            'ProcessId': 12345,
            'match': ['test','test2'],
            'timestamp': datetime.now(),
            }
        #resp = es.index(index="test", id=1, document=doc)
        #print(resp)
    except Exception as e:
        print("[!] Unable to reach elasticsearch server:")
        print("")

def elk_update(data):
    print(data)
    try:
        print("Parameters:",elk_srv,elk_port,elk_index_name,elk_username,elk_pass)
        es = Elasticsearch([{'host': elk_srv.strip(), 'port': elk_port,'scheme':"https"}],http_auth=(elk_username, elk_pass),verify_certs=False)
        resp = es.index(index= elk_index_name, document=data)
        print(resp)
    except Exception as e:
        print("[!] Unable to update data to elasticsearch server:",e)


def get_win32_processes():
    fw = wmi.WMI()
    return fw

def yara_check(yarafile):
    fh = open(yarafile)
    print("[+] Checking yara rules.")
    print("-------------------------------------------")
    print(" ")
    rules = yara.compile(file=fh)
    fh.close()
    fw = wmi.WMI()
    for process in fw.Win32_Process():
        try:
            mat = rules.match(pid=process.ProcessId)
            if len(mat) != 0:
                print("Output:",process.ProcessId,process.Name,process.GetOwner()[2],'|'.join([str(elem) for elem in mat]))
                edata = {
                    'Client': os.getenv('COMPUTERNAME'),
                    'ProcessName': process.Name,
                    'ProcessOwner': process.GetOwner()[2],
                    'ProcessId': process.ProcessId,
                    'match': '|'.join([str(elem) for elem in mat]),
                    'timestamp': datetime.now(),
                }
                if elk_set == 'Y':
                    elk_update(edata)

        except Exception as e:
            print("Output(e):",process.ProcessId,process.Name,process.GetOwner()[2],e)


def yara_checkd(filepaths):
    print("[+] Checking yara multiple rules.")
    print("-------------------------------------------")
    print(" ")
    rules = yara.compile(filepaths=filepaths)
    fw = wmi.WMI()
    for process in fw.Win32_Process():
        try:
            mat = rules.match(pid=process.ProcessId)
            if len(mat) != 0:
                print("Output:",process.ProcessId,process.Name,process.GetOwner()[2],'|'.join([str(elem) for elem in mat]))
                edata = {
                    'Client': os.getenv('COMPUTERNAME'),
                    'ProcessName': process.Name,
                    'ProcessOwner': process.GetOwner()[2],
                    'ProcessId': process.ProcessId,
                    'match': '|'.join([str(elem) for elem in mat]),
                    'timestamp': datetime.now(),
                }
                if elk_set == 'Y':
                    elk_update(edata)

        except Exception as e:
            print("Output(e):",process.ProcessId,process.Name,process.GetOwner()[2],e)


def yara_file_options(yarafile):
        try:
            print("[+] Testing yara file option")
            print("-------------------------------------------")
            print(" ")
            if os.path.exists(yarafile):
                print("[+] Processing yara rule on all processes:",type(args.yf),args.yf)
                yara_check(yarafile)
                #return True
            else:
                #return False
                print("[!] Error Processing yara file:",type(args.yf),args.yf)
        except Exception as e:
            print("[!] Error processing yara file.",e)
            #return False

def yara_dir_option(directory):
        filepaths = {}
        try:
            print("[+] Testing yara directory option")
            print("-------------------------------------------")
            print(" ")
            if directory is not None:
                    for root, dirs, files in os.walk(directory, topdown=False):
                        for filename in files:
                            #print(os.path.join(root, name))
                            filepaths.update({filename:os.path.join(root, filename)})
                    #print(filepaths)
                    #rules = yara.compile(filepaths=filepaths)
                    '''
                    fw = wmi.WMI()
                    for process in fw.Win32_Process():
                        try:
                            mat = rules.match(pid=process.ProcessId)
                            if len(mat) != 0:
                                print("Output:",process.ProcessId,process.GetOwner()[2],process.Name,mat)
                        except Exception as e:
                            print("Output:",process.ProcessId,process.GetOwner()[2],process.Name,e)
                    '''
            else:
                print("[!] Unable to find a correct yara directory")
            yara_checkd(filepaths)
        except:
            print("")

if __name__ == "__main__":
    print(banner)
    parser = argparse.ArgumentParser()
    parser.add_argument("-yf", help="Filename,Name of yara file",type=str,nargs='?')
    parser.add_argument("-yd", help="Dirpath, Parse multiple yara file in dir",type=str,nargs='?')
    parser.add_argument("-es", help="Forward logs to elasticsearch(Y/N)",type=str,default='N',nargs='?')
    args = parser.parse_args()

    if args.es == 'Y' or args.es == 'y' :
        elk_check()

    if (args.yf):
        yara_file_options(args.yf)
        print("[+] Yara file scan completed")
        print(" ")
    elif (args.yd) :
        print("[!] Yara file option not set , trying dir option")
        yara_dir_option(args.yd)
        print(" ")
    else:
        print("[!] Usage: Run \"python yaraedr.py -h\" for help" )
