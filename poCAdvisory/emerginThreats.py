import requests
from bs4 import BeautifulSoup
import re
import requests
import re
import os
import sys
import configparser
import time
import datetime
import psycopg2
import json
from lib.dateConvert import dateConvert


class emerginThreats():
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
            
    def getMetaNVD(self, cve_id):
        conn = sqlite3.connect('/var/DB/nvdDB.db')

        c = conn.cursor()
        cmd = "select distinct(cveProductVendorTab.cve_id), cveProductVendorTab.details, cveProductVendorTab.publishedDate, cvssV3Tab.attackVector, cvssV3Tab.vectorString, cvssV3Tab.baseScore, cvssV3Tab.baseSeverity, cvssV2Tab.accessVector, cvssV2Tab.vectorString, cvssV2Tab.baseScore, cvssV2Tab.severity, cveProductVendorTab.cwe_text from cveProductVendorTab INNER JOIN cvssV3Tab ON cveProductVendorTab.cve_id = cvssV3Tab.cve_id INNER JOIN cvssV2Tab ON cveProductVendorTab.cve_id = cvssV2Tab.cve_id where cveProductVendorTab.cve_id='%s'" % cve_id
        c.execute(cmd)

        results = {}

        for row in c.fetchall():
            cve_id = row[0]
            details = row[1]
            publishedDate = row[2]
            v3attackVector = row[3]
            v3vectorString = row[4]
            v3baseScore = row[5]
            v3baseSeverity = row[6]
            v2accessVector = row[7]
            v2vectorString = row[8]
            v2baseScore = row[9]
            v2severity = row[10]
            cwe_text = row[11]
           

            results['cwe_text'] = cwe_text
            results['pub_date'] = publishedDate

            if v3attackVector:
                results['accessVector'] = v3attackVector
            elif v2accessVector:
                results['accessVector'] = v2accessVector
            else:
                results['accessVector'] = ''

            if v3baseScore:
                results['baseScore'] = v3baseScore
            elif v2baseScore:
                results['baseScore'] = v2baseScore
            else:
                results['baseScore'] = ''

            if v3baseSeverity:
                results['severity'] = v3baseSeverity
            elif v2severity:
                results['severity'] = v2severity
            else:
                results['severity'] = ''

            if v3vectorString:
                results['vectorString'] = v3vectorString
            elif v2vectorString:
                results['vectorString'] = v2vectorString
            else:
                results['vectorString'] = ''

        return results


    def initialize(self, date_update):
        furl = 'https://rules.emergingthreats.net/open/'

        self.mylist = []
        myDir = self.test(furl)
        myDir1 = self.testDir1(myDir)
        myDir2 = self.testDir2(myDir1)

        urlLists = []
        for url in self.mylist:
            if 'https' in url:
                urlLists.append(url)

        for url in urlLists:
            reference = url
            cveLists = []
            description = ''
            vuln_name = ''
            details = {}
            pub_date = ''
            
            page = requests.get(url)
            soup = BeautifulSoup(page.content, "html.parser")

            if re.findall(r'cve,(\d+-\d+)', str(soup)):
                cves = re.findall(r'cve,(\d+-\d+)', str(soup))
                for cve in cves:
                    cve1 = 'CVE-%s' % cve
                    if cve1 not in cveLists:
                        cveLists.append(cve1)

            if re.findall(r'(CVE-\d+-\d+)', str(soup)):
                cves = re.findall(r'(CVE-\d+-\d+)', str(soup))
                for cve in cves:
                    if cve not in cveLists:
                        cveLists.append(cve)


            for cve_id in cveLists:
                cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{cve_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='emergingthreats')
                print(cmd)
                self.cursor.execute(cmd)
                self.connection.commit()


    def test(self, furl):
        myDir = []

        page = requests.get(furl)
        soup = BeautifulSoup(page.content, "html.parser")

        d = soup.findAll('a')
        i = 0
        for d1 in d:
            surl =  d1.get('href')
    
            if re.findall(r'.rules$', str(surl)):
                self.mylist.append('https://rules.emergingthreats.net/open/%s' % surl)

            if i == 0:
                pass
            else:
                if re.findall(r'\/$', str(surl)):
                    myDir.append('https://rules.emergingthreats.net/open/%s' % surl)
            i = i + 1

        return myDir

    def testDir1(self, myDir1):
        myDir = []
        for myd in myDir1:
            furl = myd
            try:
                page = requests.get(furl)
                soup = BeautifulSoup(page.content, "html.parser")

                d = soup.findAll('a')
                i = 0
                for d1 in d:
                    surl =  d1.get('href')

                    if re.findall(r'.rules$', str(surl)):
                        self.mylist.append('%s%s' % (myd, surl))

                    if i == 0:
                        pass
                    else:
                        if re.findall(r'\/$', str(surl)):
                            myDir.append('%s%s' % (myd, surl))
                    i = i + 1
            except:
                pass

        return myDir


    def testDir2(self, myDir1):
        myDir = []
        for myd in myDir1:
            furl = myd
            try:
                page = requests.get(furl)
                soup = BeautifulSoup(page.content, "html.parser")

                d = soup.findAll('a')
                i = 0
                for d1 in d:
                    surl =  d1.get('href')

                    if re.findall(r'.rules$', str(surl)):
                        self.mylist.append('%s%s' % (myd, surl))

                    if i == 0:
                        pass
                    else:
                        if re.findall(r'\/$', str(surl)):
                            myDir.append('%s%s' % (myd, surl))

                    i = i + 1
            except:
                pass

        return myDir

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = emerginThreats()
    res.initialize(date_update) 

