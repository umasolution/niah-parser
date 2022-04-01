from bs4 import BeautifulSoup
import requests
import re
import os
import sys
import configparser
import time
import datetime
from lib.dateConvert import dateConvert
import psycopg2
import json

class moniPacketStromDB():
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
        
        sys.setrecursionlimit(100000)

    def initialize(self, date_update):
        date_update = date_update

        url = "https://packetstormsecurity.com/files/page1/"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        try:
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
            pageNoText = soup.findAll('strong')
            pageNoTemp = re.findall(r'of (.*)<', str(pageNoText))
            totalNo = pageNoTemp[0].replace(',', '')
        except:
            try:
                time.sleep(30)
                page = requests.get(url, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")
                pageNoText = soup.findAll('strong')
                pageNoTemp = re.findall(r'of (.*)<', str(pageNoText))
                totalNo = pageNoTemp[0].replace(',', '')
            except:
                pass
        
        i = 1
        while True:
            check = True
            if self.daily:
                url = "https://packetstormsecurity.com/files"
            else:
                url = "https://packetstormsecurity.com/files/page%s/" % i

            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })

            try:
                page = requests.get(url, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")
            except:
                try:
                    time.sleep(60)
                    page = requests.get(url, headers=headers)
                    soup = BeautifulSoup(page.content, "html.parser")
                except:
                    check = False
                    i = i + 1
                    pass

            if re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE) and check:
                cves = re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE)

                dls = soup.findAll('dl',{'class':'file'})

                for dl in dls:
                    vuln_name = ""
                    description = ""
                    pkt_id = ""
                    reference = ""
                    tags = ""
                    os = ""
                    platform = ""
                    dLink = ""
                    download_link = ""
                    cves = []
                    if re.findall(r'(CVE-\d+-\d+)', str(dl), re.IGNORECASE):
                        cves = re.findall(r'(CVE-\d+-\d+)', str(dl), re.IGNORECASE)
                
                    for dt in dl.findAll('dt'):
                        vuln_name = dt.text
                        vuln_name = vuln_name.replace("'", "")

                        pkt_id = re.findall(r'files\/(.*?)\/', str(dt))[0]

                    for dd in dl.findAll('dd'):
                        if re.findall(r'class="datetime', str(dd)):
                            datetime1 = dd.text
                            pub_date = datetime1.replace('Posted ', '')
                            try:
                                res1 = dateConvert()
                                pub_date = res1.dateCon(pub_date)
                            except:
                                pub_date = datetime1.replace('Posted ', '')

                        if re.findall(r'class="refer', str(dd)):
                            reference = dd.text
                            reference = reference.replace("'", "")

                        if re.findall(r'class="detail', str(dd)):
                            description = dd.text
                            description = description.replace("'", "")

                        if re.findall(r'class="tags', str(dd)):
                            tags = dd.text
                            tags = tags.replace("'", "")

                        if re.findall(r'class="os', str(dd)):
                            os = dd.text
                            platform = os.replace('systems | ', '')


                        if re.findall(r'class="act-links', str(dd)):
                            dLink = re.findall(r'"\/files\/download(\/.*?)"',  str(dd))[0]
                            download_link = "https://packetstormsecurity.com/files/download%s" % dLink
                    
                        details = {}
                        details['platform'] = platform
                        details['download'] = download_link
                        details['tags'] = tags

                    description = description.replace("'", "")
                    
                    for cve_id in cves:
                        cve_id = cve_id.strip()
                        cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{pkt_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(pkt_id=pkt_id, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='packetstorm')
                        try:
                            print(cmd)
                        except:
                            pass
                        self.cursor.execute(cmd)
                        self.connection.commit()

            i = i + 1
            if i > int(totalNo):
                break

            if self.daily:
                break
            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniPacketStromDB()
    res.initialize(date_update)
