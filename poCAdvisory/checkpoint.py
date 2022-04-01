from bs4 import BeautifulSoup
import requests
import re
import os
import sys
import configparser
import time
import datetime
from lib.dateConvert import dateConvert
import json
import psycopg2


class moniCheckpointDB():
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
        date_update = date_update
        year = datetime.datetime.now().year

        while year >= 1998:
            k = 0
            while True:
                k = k + 1
                url = "https://www.checkpoint.com/defense/advisories/public/%s/page/%s/" % (year, k)
                headers = requests.utils.default_headers()
                headers.update({
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                })

                page = requests.get(url, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")
            
                if not soup.findAll('table',{'class':'table tablesorter table-bordered table-striped'}):
                    break
            
                tables = soup.findAll('table',{'class':'table tablesorter table-bordered table-striped'})	
                trs = soup.findAll('tr')
                if len(trs) == 1:
                    break

                i = 0
                reference = ''
                description = ''
                vuln_name = ''

                for tr in trs:
                    if i == 0:
                        pass
                    else:
                        j = 0
                        for td in tr.findAll('td'):
                            if j == 0:
                                severity = td.text
                                severity = severity.strip()
                            if j == 1:
                                pub_date = td.text
                                pub_date = pub_date.strip()
                                res1 = dateConvert()
                                pub_date = res1.dateCon(pub_date)
                            if j == 3:
                                checkp_refe = td.text
                                checkp_refe = checkp_refe.strip()
                                reference = "https://www.checkpoint.com/defense/advisories/public/%s/%s.html" % (year, checkp_refe)
                            if j == 4:
                                source = td.text
                                source = source.strip()
                            if j == 5:
                                cve_ids = td.text
                                cve_ids = cve_ids.strip()
                                cves = []
                                if re.findall(r'(CVE-\d+-\d+)', str(cve_ids), re.IGNORECASE):
                                    for cve_id in re.findall(r'(CVE-\d+-\d+)', str(cve_ids), re.IGNORECASE):
                                        cves.append(cve_id)
                                else:
                                    cves.append('Not Available')
                            if j == 6:
                                description = td.text
                                description = description.strip()
                                description = description.replace("'", "")
                                vuln_name = description
                            j = j + 1

                        details = {}
                        details['severity'] = severity
                        details['source'] = source

                        for cve_id in cves:
                            cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{checkp_refe}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(checkp_refe=checkp_refe, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='checkpoint')
                            print(cmd)
                            self.cursor.execute(cmd)
                            self.connection.commit()
                    i = i + 1

                if self.daily:
                    break

            year -= 1

            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniCheckpointDB()
    res.initialize(date_update)
