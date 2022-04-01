from bs4 import BeautifulSoup
import requests
import re
import os
import sys
import configparser
import time
import datetime
import json
import psycopg2
from lib.dateConvert import dateConvert


class moniNessusDB():
    def __init__(self):
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        hostName = self.settings.get('database', 'host')
        userName = self.settings.get('database', 'user')
        password = self.settings.get('database', 'pass')
        databaseName = self.settings.get('database', 'dbname')

        self.connection = psycopg2.connect(user=userName,password=password,host=hostName,port="5432",database=databaseName)
        self.cursor = self.connection.cursor()   
    

    def initialize(self, date_update):
        print("[ OK ] Initialize Nessus Update sync")
        self.initializeUpdate(date_update)
        print("[ OK ] Initialize Nessus new sync")
        self.initializeNew(date_update)

    def initializeNew(self, date_update):
        date_update = date_update
        year = datetime.datetime.now().year

        url = "https://www.tenable.com/cve/newest?page=1"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })
        page = requests.get(url, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        i = 1
        while True:
            if self.daily:
                url = "https://www.tenable.com/cve/newest?page=1"
            else:
                url = "https://www.tenable.com/cve/newest?page=%s" % i

            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })

            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
                
            if not soup.findAll('table',{'class':'table'}):
                break
                        
            table = soup.findAll('table',{'class':'table'})[0]	
            tbody = table.findAll('tbody')[0]

            for trs in tbody.findAll('tr'):
                j = 0
                description = ''
                vuln_name = ''
                severity = ''
                pub_date = ''
                
                for tds in trs.findAll('td'):
                    if j == 0:
                        cve_id = tds.text
                    if j == 1:
                        desc1 = tds.text
                        desc1 = desc1.replace("'", "")
                        description = desc1.replace("'", "")
                        vuln_name = description
                    if j == 2:
                        severity = tds.text
                    j = j + 1

                    reference = "https://www.tenable.com/cve/%s" % cve_id
                    details = {}
                    details['severity'] = severity
                    pub_date = ''
                    cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{cve_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='nessus')
                    print(cmd)
                    self.cursor.execute(cmd)
                    self.connection.commit()

            i = i + 1
            if self.daily:
                break
  
    def initializeUpdate(self, date_update):
        date_update = date_update
        year = datetime.datetime.now().year

        url = "https://www.tenable.com/cve/updated?page=1"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })
        page = requests.get(url, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        i = 1
        while True:
            if self.daily:
                url = "https://www.tenable.com/cve/newest?page=1"
            else:
                url = "https://www.tenable.com/cve/newest?page=%s" % i

            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })

            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")

            if not soup.findAll('table',{'class':'table'}):
                break

            table = soup.findAll('table',{'class':'table'})[0]
            tbody = table.findAll('tbody')[0]

            for trs in tbody.findAll('tr'):
                j = 0
                description = ''
                vuln_name = ''
                severity = ''
                pub_date = ''
                
                for tds in trs.findAll('td'):
                    if j == 0:
                        cve_id = tds.text
                    if j == 1:
                        desc1 = tds.text
                        desc1 = desc1.replace("'", "")
                        description = desc1.replace("'", "")
                        vuln_name = description
                    if j == 2:
                        severity = tds.text
                    j = j + 1

                    reference = "https://www.tenable.com/cve/%s" % cve_id
                    details = {}
                    details['severity'] = severity

                    pub_date = ''
                    cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{cve_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='nessus')
                    print(cmd)
                    self.cursor.execute(cmd)
                    self.connection.commit()
                      
            i = i + 1
            if self.daily:
                break
         
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniNessusDB()
    res.initialize(date_update)
