#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
Author      : Oguzcan Pamuk
Date        : 01.08.2021
Description : A tool that detects the "expensive" Carbon Black watchlists.
References  :
    - https://developer.carbonblack.com/reference/enterprise-response/6.3/rest-api/#watchlist-operations
    - https://community.carbonblack.com/t5/Knowledge-Base/EDR-Are-there-Best-Practices-for-Performance-When-Writing-a/ta-p/88599
'''

'''
Requirements:
    - pip install configparser,requests
    - CB API Key
    - CB URL & Port
'''

import requests
import sys
from datetime import datetime
import time
from urllib.parse import unquote
import configparser
import csv
import warnings
warnings.filterwarnings('ignore')

PROGRAM_NAME = '''

  ______  ______   _______                                    _              
 / _____)(____  \ (_______)                                  (_)             
| /       ____)  ) _____    _   _  ____    ____  ____    ___  _  _   _  ____ 
| |      |  __  ( |  ___)  ( \ / )|  _ \  / _  )|  _ \  /___)| || | | |/ _  )
| \_____ | |__)  )| |_____  ) X ( | | | |( (/ / | | | ||___ || | \ V /( (/ / 
 \______)|______/ |_______)(_/ \_)| ||_/  \____)|_| |_|(___/ |_|  \_/  \____)
                                  |_|                                        
          
'''

FILENAME = "result"
EXTENTION = ".csv"
URL_WATCHLIST = "/api/v1/watchlist"
QUERY_REPLACE = "cb.urlver=1&q="
SUCCESS_CODE = 200
UNAUTHORIZED_CODE = 401
CONFIG_FILE_NAME = "config.ini"
OR_OPERATOR = "OR"
WILDCARD = "*"
FILEMOD_SYNTAX = "filemod:"
MODLOAD_SYNTAX = "modload:"
EQUAL = "="
SEARCH_FIELDS = ['blocked_md5', 'blocked_status', 'childproc_count', 'childproc_md5', 'childproc_sha256', 'childproc_name', 'cmdline',
                'comments', 'company_name', 'copied_mod_len', 'crossproc_count', 'crossproc_md5', 'crossproc_sha256', 'crossproc_name', 
                'crossproc_type', 'digsig_issuer', 'digsig_prog_name', 'digsig_publisher', 'digsig_result', 'digsig_sign_time', 'digsig_subject',
                'domain', 'file_desc', 'file_version', 'filemod', 'filemod_count', 'filewrite_md5', 'filewrite_sha256', 'group', 'has_emet_config',
                'has_emet_event', 'host_count', 'host_type', 'hostname', 'internal_name', 'ipaddr', 'ipv6addr', 'ipport', 'is_64bit', 'is_executable_image',
                'ja3', 'ja3s', 'last_server_update', 'last_update', 'legal_copyright', 'legal_trademark', 'md5', 'sha256', 'modload', 'modload_count',
                'netconn_count', 'observed_filename', 'orig_mod_len', 'original_filename', 'os_type', 'parent_id', 'parent_md5', 'parent_sha256',
                'parent_name', 'path', 'private_build', 'process_id', 'process_md5', 'process_sha256', 'process_name', 'product_desc', 'product_name',
                'product_version', 'regmod', 'regmod_count', 'sensor_id', 'server_added_timestamp', 'special_build', 'start', 'tampered', 'username']

def readConfigFile():

    try:
        configParser = configparser.RawConfigParser()
        configFilePath = CONFIG_FILE_NAME
        configParser.read(configFilePath)
        api_key = configParser.get('APIKEY', 'API_KEY')
        url = configParser.get('URL', 'CB_URL')
        port = configParser.get('URL', 'CB_PORT')
    except configparser.NoOptionError as error:
        print ("Error in options Name", error)
        sys.exit()
    except configparser.NoSectionError as error:
        print ("Error in sections Name", error)
        sys.exit()
    except configparser.ParsingError as error:
        print ('Could not parse:', error)

    return api_key,url,port

def getWatchlists(url,port,api_key):
    headers = {'X-Auth-Token':api_key}
    watchtlist_details=[]

    try:
        response = requests.get(url + ":"+ port + URL_WATCHLIST, headers=headers, verify=False, timeout=5)
        if (response.status_code == UNAUTHORIZED_CODE):
            print ("Authentication Token is invalid or expired!")
            sys.exit()
        elif(response.status_code == SUCCESS_CODE):
            watchlists = response.json()
            for watchlist in watchlists:
                query = str(unquote(watchlist['search_query']).replace(QUERY_REPLACE,"").strip())
                enabled = bool(watchlist['enabled'])
                executionTimeMs = (watchlist['last_execution_time_ms'])
                lastHit = str(watchlist['last_hit'])
                if lastHit != "None":
                    lastHit = datetime.strptime(lastHit.split(".")[0], '%Y-%m-%d %H:%M:%S')

                details = {
                    "query": query,
                    "enabled": enabled,
                    "execution_time": executionTimeMs,
                    "last_hit": lastHit
                }

                watchtlist_details.append(details)
        else:
            print ("An unexpected error has occurred. Please check Carbon Black url and port.")
            sys.exit()
    except requests.exceptions.Timeout:
        print("Connection could not be established")
        sys.exit()

    return watchtlist_details


def calculateOROperatorCount(query):
    return query.count(OR_OPERATOR)

def calculateWildcardCount(query):
    return query.count(WILDCARD)

def filemodWildcardControl(query):
    if query.count(FILEMOD_SYNTAX) > 0:
        for subquery in query.split(" "):
            if FILEMOD_SYNTAX in subquery and WILDCARD in subquery:
                return True
    return False

def modloadWildcardControl(query):
    if query.count(MODLOAD_SYNTAX) > 0:
        for subquery in query.split(" "):
            if MODLOAD_SYNTAX in subquery and WILDCARD in subquery:
                return True
    return False

def equalOperatorControl(query):
    for field in SEARCH_FIELDS:
        if field+EQUAL in query:
            return True
    
    return False

def main():
    print (PROGRAM_NAME)
    api_key,url,port = readConfigFile()
    watchlists = getWatchlists(url,port,api_key)
    timeForFilename = time.strftime("%Y%m%d-%H%M%S")
    output = open(FILENAME+timeForFilename+EXTENTION, mode='w')
    output_writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    output_writer.writerow(['Query','ExecutionTime','NumberofWildcard', 'WildcardwithFilemod', 'WildcardwithModload', 'EqualOperator', 'NumberofOROperator'])

    for watchlist in watchlists:
        query = watchlist['query']
        execution_time = watchlist['execution_time']
        output_writer.writerow([str(query),str(execution_time),str(calculateWildcardCount(query)),str(filemodWildcardControl(query)),
                                str(modloadWildcardControl(query)),str(equalOperatorControl(query)), str(calculateOROperatorCount(query))])

if __name__ == "__main__":
    main()
