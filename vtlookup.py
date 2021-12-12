#!/usr/bin/env python3

"""
Name:           vtlookup.py
Modified:       12 DEC 2021
Author:         Mark Bradley
Description:    Lookup file hash values using VirusTotal API v3
License:        MIT (https://opensource.org/licenses/MIT)
"""


import json
import requests
import hashlib
import os
import argparse
from datetime import datetime


def usage():
    print('''

    USAGE EXAMPLES:

    By plain text hash -
    > python3 vtlookup.py -hash 4534c2d2d89c40929adb71f9d52b650c

    By getting has from a file on system
    > python3 vtlookup.py -file myfile.ext

    Offline debug using local json file
    > python3 vtlookup.py -debug text.json

    ''')


def missing_api_key():
    print('''
    
    A VirusTotal public API key is required and must be set as an environment variable.
    Please set the environment variable with a name of VT_API_KEY.

    If you don't have a key signup at https://www.virustotal.com/gui/join-us.

    Use the following terminal commands:

    For Linux users -
    > VT_API_KEY="YOUR_VIRUSTOTAL_APIKEY"
    > export VT_API_KEY

    For Windows users -
    > setx VT_API_KEY "YOUR_VIRUSTOTAL_APIKEY"
    
    ''')


def block_heading(text):
    """
    Displays a block heading inside formatted box
    """
    header_text = text.upper()
    header_length = len(header_text)
    box_width = int(header_length)
    print(f'')
    print(f'{"+":-<{box_width+5}}+')
    print(f'{"|":<3}{header_text:^{box_width}}{"|":>3}')
    print(f'{"+":=<{box_width+5}}+')
    print(f'')


def hash_file(filename):
    """
    Return sha256 hash value of filename
    """
    if os.path.isfile(filename):
        h = hashlib.sha256()
        with open(filename, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
        print(f'sha256 hash of {filename}: {h.hexdigest()}')
        return h.hexdigest()
    else:
        print(
            f'ERROR: {filename} does not exist. Check the file path location.\n')
        exit(1)


def vt_lookup(hashValue, apiKey):
    """
    Perform API lookup on hash value and return json data results
    """
    print(f'VirusTotal report details for file hash: {hashValue}\n')
    url = f'https://www.virustotal.com/api/v3/files/{hashValue}'
    headers = {
        'x-apikey': apiKey,
        'Accept': 'application/json',
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if "404" in str(e):
            print(
                '404 response returned likely meaning no file hash matches have been found.\n')
        else:
            print(f'API response: {e}')
            print(
                'For more information visit: https://developers.virustotal.com/reference/errors\n')
        exit(1)


def format_json(data):
    """
    Format JSON data in readable terminal output
    """
    total_vendors = 0
    total_detections = 0
    if "data" in data:
        for k, v in data["data"]["attributes"]["last_analysis_results"].items():
            total_vendors += 1
            if str(v["result"]) != "None":
                total_detections += 1
                print("\033[91m{:<30} {:<30}\033[0m".format(
                    k, str(v["result"])))
        print(
            f'\n\033[1m\033[91mWARNING: {total_detections} of {total_vendors} security vendors flagged a file with this hash value as malicious\033[0m')
        basicProp = {
            "First submission date": str(datetime.fromtimestamp(data["data"]["attributes"]["first_submission_date"])),
            "Last analysis date": str(datetime.fromtimestamp(data["data"]["attributes"]["last_analysis_date"])),
            "ssdeep": data["data"]["attributes"]["ssdeep"],
            "sha256": data["data"]["attributes"]["sha256"],
            "sha1": data["data"]["attributes"]["sha1"],
            "md5": data["data"]["attributes"]["md5"]
        }
        block_heading("Basic Properties")
        for k, v in basicProp.items():
            print("{:<30} {:<30}".format(k, str(v)))
        print('')
    else:
        print("ERROR: No data found in json data.")


def vt_debug(jsonFile):
    """
    Read an offline Virustotal JSON data file
    """
    block_heading(f'Debug using offline jsonFile: {jsonFile}')
    with open(jsonFile) as f:
        data = json.load(f)
    return data


def main():
    """
    Main function to check for API key and commandline arguments
    """
    block_heading(f'VirusTotal Hash Lookup')
    try:
        apiKey = os.environ["VT_API_KEY"]
    except KeyError:
        missing_api_key()
        exit(1)
    parser = argparse.ArgumentParser(
        description='Lookup hash value using Virustotal')
    parser.add_argument("-file", "--filename", help="Hash of filename")
    parser.add_argument("-hash", "--hashvalue", help="Hash value")
    parser.add_argument("-debug", "--debug",
                        help="Debug using local JSON data file")
    args = parser.parse_args()

    if args.filename:
        hashValue = hash_file(args.filename)
        data = vt_lookup(hashValue, apiKey)
    elif args.hashvalue:
        data = vt_lookup(args.hashvalue, apiKey)
    elif args.debug:
        data = vt_debug(args.debug)
    else:
        parser.print_help()
        usage()
        exit(1)
    format_json(data)


if __name__ == "__main__":
    main()
