import sys
import os.path
from os import path
import collections
from tqdm import tqdm
import datetime
import re
import datetime
import subprocess
import os
import configparser
import ast
import datetime
import logging
import time
import json
from collections import defaultdict
import sys
from itertools import groupby
from operator import itemgetter
from pprint import pprint
from itertools import chain
from dateConvert import dateConvert
import json
import psycopg2
import sqlite3

class feedGen():
    def __init__(self):
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        hostName = self.settings.get('database', 'host')
        userName = self.settings.get('database', 'user')
        password = self.settings.get('database', 'pass')
        databaseName = self.settings.get('database', 'dbname')
        self.date_update = date_update

        self.connection = psycopg2.connect(user=userName,password=password,host=hostName,port="5432",database=databaseName)
        self.cursor = self.connection.cursor()


    def nvdFetch(self, date_update):
        results1 = {}
        results1['publishDate'] = date_update
        results1['vendor'] = {}
        results1['product'] = {}
        results1['vulnerabilities'] = {}

        year = datetime.datetime.now().year

        while year >= 2001:
            print("[ OK ] %s processing started" % year)
            with open("/var/DB/feeds/nvd/%s_db.json" % year, "r") as f:
                jsonData = json.load(f)

            results = {}
            results['publishDate'] = date_update
            results[year] = {}
            results[year]['vendor'] = {}
            results[year]['product'] = {}
            results[year]['vulnerabilities'] = {}

            for data in tqdm(jsonData):
                cve_id = data
                v2severity2 = jsonData[data]['baseseverity2']
                v2severity3 = jsonData[data]['baseseverity3']

                if v2severity2 and v2severity3:
                    v2severity = v2severity3
                elif not v2severity2 and v2severity3:
                    v2severity = v2severity3
                elif v2severity2 and not v2severity3:
                    v2severity = v2severity2
                else:
                    v2severity = v2severity2

                cwe_text = jsonData[data]['cwe_text']
                cwe_str = jsonData[data]['cwe_str']

                if len(jsonData[data]['products']) > 0:
                    for p in jsonData[data]['products']:
                        vendor = p['vendor']
                        product = p['product']
                        appVendor = p['appVendor']
                        type = p['type']
                
                        if product not in results[year]['product']:
                            results[year]['product'][product] = {}
                            results[year]['product'][product]['vendor'] = vendor 
                            results[year]['product'][product]['type'] = type 
                            results[year]['product'][product]['totalvuln'] = 1
                            results[year]['product'][product]['severity'] = {}
                        else:
                            results[year]['product'][product]['totalvuln'] = results[year]['product'][product]['totalvuln'] + 1

                        if vendor not in results[year]['vendor']:
                            results[year]['vendor'][vendor] = {}
                            results[year]['vendor'][vendor]['products'] = []
                            results[year]['vendor'][vendor]['totalvuln'] = 1
                            results[year]['vendor'][vendor]['severity'] = {}
                        else:
                            results[year]['vendor'][vendor]['totalvuln'] = results[year]['vendor'][vendor]['totalvuln'] + 1

                        if product not in results[year]['vendor'][vendor]['products']:
                            results[year]['vendor'][vendor]['products'].append(product)

                        if v2severity not in results[year]['product'][product]['severity']:
                            results[year]['product'][product]['severity'][v2severity] = 1
                        else:
                            results[year]['product'][product]['severity'][v2severity] = results[year]['product'][product]['severity'][v2severity] + 1

                        if v2severity not in results[year]['vendor'][vendor]['severity']:
                            results[year]['vendor'][vendor]['severity'][v2severity] = 1
                        else:
                            results[year]['vendor'][vendor]['severity'][v2severity] = results[year]['vendor'][vendor]['severity'][v2severity] + 1
            
                        if cwe_text not in results[year]['vulnerabilities']:
                            results[year]['vulnerabilities'][cwe_text] = {}
                            results[year]['vulnerabilities'][cwe_text]['name'] = cwe_str
                            results[year]['vulnerabilities'][cwe_text]['totalvuln'] = 1
                            results[year]['vulnerabilities'][cwe_text]['severity'] = {}
                        else:
                            results[year]['vulnerabilities'][cwe_text]['totalvuln'] = results[year]['vulnerabilities'][cwe_text]['totalvuln'] + 1

                        if v2severity not in results[year]['vulnerabilities'][cwe_text]['severity']:
                            results[year]['vulnerabilities'][cwe_text]['severity'][v2severity] = 1
                        else:
                            results[year]['vulnerabilities'][cwe_text]['severity'][v2severity] = results[year]['vulnerabilities'][cwe_text]['severity'][v2severity] + 1

                        # For all years
                        if product not in results1['product']:
                            results1['product'][product] = {}
                            results1['product'][product]['vendor'] = vendor 
                            results1['product'][product]['type'] = type
                            results1['product'][product]['totalvuln'] = 1
                            results1['product'][product]['severity'] = {}
                        else:
                            results1['product'][product]['totalvuln'] = results1['product'][product]['totalvuln'] + 1

                        if vendor not in results1['vendor']:
                            results1['vendor'][vendor] = {}
                            results1['vendor'][vendor]['products'] = []
                            results1['vendor'][vendor]['totalvuln'] = 1
                            results1['vendor'][vendor]['severity'] = {}
                        else:
                            results1['vendor'][vendor]['totalvuln'] = results1['vendor'][vendor]['totalvuln'] + 1

                        if product not in results1['vendor'][vendor]['products']:
                            results1['vendor'][vendor]['products'].append(product)

                        if v2severity not in results1['product'][product]['severity']:
                            results1['product'][product]['severity'][v2severity] = 1
                        else:
                            results1['product'][product]['severity'][v2severity] = results1['product'][product]['severity'][v2severity] + 1

                        if v2severity not in results1['vendor'][vendor]['severity']:
                            results1['vendor'][vendor]['severity'][v2severity] = 1
                        else:
                            results1['vendor'][vendor]['severity'][v2severity] = results1['vendor'][vendor]['severity'][v2severity] + 1
            
                        if cwe_text not in results1['vulnerabilities']:
                            results1['vulnerabilities'][cwe_text] = {}
                            results1['vulnerabilities'][cwe_text]['name'] = cwe_str
                            results1['vulnerabilities'][cwe_text]['totalvuln'] = 1
                            results1['vulnerabilities'][cwe_text]['severity'] = {}
                        else:
                            results1['vulnerabilities'][cwe_text]['totalvuln'] = results1['vulnerabilities'][cwe_text]['totalvuln'] + 1

                        if v2severity not in results1['vulnerabilities'][cwe_text]['severity']:
                            results1['vulnerabilities'][cwe_text]['severity'][v2severity] = 1
                        else:
                            results1['vulnerabilities'][cwe_text]['severity'][v2severity] = results1['vulnerabilities'][cwe_text]['severity'][v2severity] + 1

            temp_results = []
            for product in results[year]['product']:
                res = {}
                res['product'] = product
                res['totalvuln'] = results[year]['product'][product]['totalvuln']
                res['severity'] = results[year]['product'][product]['severity']
                res['vendor'] = results[year]['product'][product]['vendor']
                res['producttype'] = results[year]['product'][product]['type']
                temp_results.append(res)
    
            filedata = {}
            filedata['product'] = sorted(temp_results, key=lambda k: k.get('totalvuln', 0), reverse=True)

            temp_results = []
            for vendor in results[year]['vendor']:
                res = {}
                res['vendor'] = vendor
                res['totalvuln'] = results[year]['vendor'][vendor]['totalvuln']
                res['severity'] = results[year]['vendor'][vendor]['severity']
                res['totalpackages'] = len(results[year]['vendor'][vendor]['products'])
                temp_results.append(res)
    
            filedata['vendor'] = sorted(temp_results, key=lambda k: k.get('totalvuln', 0), reverse=True)

            temp_results = []
            for vulnerabilities in results[year]['vulnerabilities']:
                res = {}
                res['cwe_text'] = vulnerabilities
                res['totalvuln'] = results[year]['vulnerabilities'][vulnerabilities]['totalvuln']
                res['severity'] = results[year]['vulnerabilities'][vulnerabilities]['severity']
                res['name'] = results[year]['vulnerabilities'][vulnerabilities]['name']
                temp_results.append(res)
    
            filedata['vulnerabilities'] = sorted(temp_results, key=lambda k: k.get('totalvuln', 0), reverse=True)

            json_object = json.dumps(filedata, indent = 4)
            with open("/var/DB/feeds/browse/%s.json" % year, "w") as outfile:
                outfile.write(json_object)

            year -= 1

        temp_results1 = []
        for product in results1['product']:
            res = {}
            res['product'] = product
            res['totalvuln'] = results1['product'][product]['totalvuln']
            res['severity'] = results1['product'][product]['severity']
            res['vendor'] = results1['product'][product]['vendor']
            res['producttype'] = results1['product'][product]['type']
            temp_results1.append(res)
    
        filedata = {}
        filedata['product'] = sorted(temp_results1, key=lambda k: k.get('totalvuln', 0), reverse=True)

        temp_results1 = []
        for vendor in results1['vendor']:
            res = {}
            res['vendor'] = vendor
            res['totalvuln'] = results1['vendor'][vendor]['totalvuln']
            res['severity'] = results1['vendor'][vendor]['severity']
            res['totalpackages'] = len(results1['vendor'][vendor]['products'])
            temp_results1.append(res)
    
        filedata['vendor'] = sorted(temp_results1, key=lambda k: k.get('totalvuln', 0), reverse=True)

        temp_results1 = []
        for vulnerabilities in results1['vulnerabilities']:
            res = {}
            res['cwe_text'] = vulnerabilities
            res['totalvuln'] = results1['vulnerabilities'][vulnerabilities]['totalvuln']
            res['severity'] = results1['vulnerabilities'][vulnerabilities]['severity']
            res['name'] = results1['vulnerabilities'][vulnerabilities]['name']
            temp_results1.append(res)
    
        filedata['vulnerabilities'] = sorted(temp_results1, key=lambda k: k.get('totalvuln', 0), reverse=True)

        json_object = json.dumps(filedata, indent = 4)
        with open("/var/DB/feeds/browse/allcves.json", "w") as outfile:
            outfile.write(json_object)


if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = feedGen()
    res.nvdFetch(date_update)
