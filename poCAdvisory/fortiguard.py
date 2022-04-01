from bs4 import BeautifulSoup
import time
import sqlite3
import requests
import datetime
import re
import sys
import configparser
from lib.dateConvert import dateConvert
import psycopg2
import json

class moniFortiguard():
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
        cmd = "select distinct(cveProductVendorTab.cve_id), cveProductVendorTab.publishedDate, cveProductVendorTab.cwe_text, cvssV3Tab.attackVector, cvssV3Tab.vectorString, cvssV3Tab.baseScore, cvssV3Tab.baseSeverity, cvssV2Tab.accessVector, cvssV2Tab.vectorString, cvssV2Tab.baseScore, cvssV2Tab.severity from cveProductVendorTab INNER JOIN cvssV3Tab ON cveProductVendorTab.cve_id = cvssV3Tab.cve_id INNER JOIN cvssV2Tab ON cveProductVendorTab.cve_id = cvssV2Tab.cve_id where cveProductVendorTab.cve_id='%s'" % cve_id
        c.execute(cmd)

        results = {}
        for row in c.fetchall():
            cve_id = row[0]
            publishedDate = row[1]
            cwe_text = row[2]
            v3attackVector = row[3]
            v3vectorString = row[4]
            v3baseScore = row[5]
            v3baseSeverity = row[6]
            v2accessVector = row[7]
            v2vectorString = row[8]
            v2baseScore = row[9]
            v2severity = row[10]

            results['cwe_text'] = cwe_text
            results['publishedDate'] = publishedDate          

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

    def uniqCVEs(self, cves):
        res = []
        for cve in cves:
            if cve not in res:
                res.append(cve)
        return res
                 
    def initialize(self, date_update):
        self.date_update = date_update
        
        p = 0
        while True:
            p = p + 1
        
            if self.daily:
                if p == 2:
                    break

            url = "https://fortiguard.com/encyclopedia?type=ips&page=%s" % p

            try:
                page = requests.get(url)
                soup = BeautifulSoup(page.content, "html.parser")
            except:
                try:
                    time.sleep(300)
                    page = requests.get(url)
                    soup = BeautifulSoup(page.content, "html.parser")
                except:
                    print("[ OK ] Reconnect error with p %s" % p)
                    break

            if re.findall(r'Records could not be found at this time, Please try again later', str(soup)):
                break

            urls = []
            for aTag in soup.findAll('a'):
                aUrl = aTag.get("href")
                if re.findall(r'(\/encyclopedia\/ips\/\d+)', str(aUrl)):
                    urls.append(aUrl)

            for url in urls:
                url = "https://fortiguard.com%s" % url
                reference = url
                if re.findall(r'https:\/\/fortiguard\.com\/encyclopedia\/ips\/(.*)', str(url)):
                    sig_id = re.findall(r'https:\/\/fortiguard\.com\/encyclopedia\/ips\/(.*)', str(url))[0]
                    desc1 = ''
                    
                    cookies = {
                        'privacy_agreement': 'true',
                        'cookiesession1': '2DFBACC7VLNXLSQLV8HXJ1ZQTSUKA868',
                        '_pk_id.11.e637': 'c32e8ac3947e9403.1611020901.2.1611167679.1611020901.',
                    }

                    headers = {
                        'Connection': 'keep-alive',
                        'Cache-Control': 'max-age=0',
                        'sec-ch-ua': '"Google Chrome";v="87", " Not;A Brand";v="99", "Chromium";v="87"',
                        'sec-ch-ua-mobile': '?0',
                        'Upgrade-Insecure-Requests': '1',
                        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                        'Sec-Fetch-Site': 'none',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-User': '?1',
                        'Sec-Fetch-Dest': 'document',
                        'Accept-Language': 'en-US,en;q=0.9',
                    }

                    time.sleep(10)
                    try:
                        page = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                        soup = BeautifulSoup(page.content, "html.parser")
                    except:
                        try:
                            print("sleep")
                            time.sleep(120)
                            page = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                            soup = BeautifulSoup(page.content, "html.parser")
                        except:
                            break
                            print("[ OK ] Reconnect error with p %s" % p)


                    if re.findall(r'Could not retrieve this IPS entry at this time. Please try again later', str(soup)):
                        print("Sleep")
                        time.sleep(320)
                        try:
                            page = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                            soup = BeautifulSoup(page.content, "html.parser")
                        except:
                            break
                            print("[ OK ] Reconnect error with p %s" % p)

                    try:
                        desc1 = soup.findAll('h2', {'class': 'title'})[0].text
                        desc1 = desc1.replace("'", "")
                    except:
                        print("sleep1")
                        time.sleep(320)
                        try:
                            page = requests.get(url, headers=headers, cookies=cookies, timeout=10)
                            soup = BeautifulSoup(page.content, "html.parser")
                        except:
                            print("[ OK ] Reconnect error with p %s" % p)

                    try:
                        sideBarText = soup.findAll('div', {'class':'sidebar-content'})[0]
                        tableMeta = sideBarText.findAll('table', {'class':'table table-responsive table-borderless'})[0]
                        pub_date = ''
                        i = 0
                        for tr in tableMeta.findAll('tr'):
                            if i == 1:
                                j = 0
                                for td in tr.findAll('td'):
                                    if j == 1:
                                        pub_date = td.text
                                    j = j + 1

                            if not pub_date:
                                if i == 2:
                                    j = 0
                                    for td in tr.findAll('td'):
                                        if j == 1:
                                            pub_date = td.text
                                        j = j + 1
                
                            i = i + 1
                        res1 = dateConvert()
                        pub_date = res1.dateCon(pub_date)
                    except:
                        pub_date = ''	

                    description = desc1
                    vuln_name = description

                    if re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE):
                        cves = re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE)
                        cves = self.uniqCVEs(cves)
                    else:
                        cves = []

                    if len(cves) > 0:	
                        for cve_id in cves:
                            #res = self.getMetaNVD(cve_id)
                            res = {}
                            if 'severity' in res:
                                severity = res['severity']
                            else:
                                severity = ''

                            if not pub_date:
                                if 'pub_date' in res:
                                    pub_date = res['publishedDate']
                                else:
                                    pub_date = ''

                            details = {}
                            details['severity'] = severity

                            cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{sig_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(sig_id=sig_id, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='fortiguard')
                            print(cmd)
                            self.cursor.execute(cmd)
                            self.connection.commit()
                    else:	
                        cve_id = ''
                        severity = ''

                        details = {}
                        cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{sig_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(sig_id=sig_id, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='fortiguard')
                        print(cmd)
                        self.cursor.execute(cmd)
                        self.connection.commit()
                else:
                    print("Signature ID not found")

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniFortiguard()
    res.initialize(date_update)
