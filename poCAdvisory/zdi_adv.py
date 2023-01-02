from bs4 import BeautifulSoup
import requests
import re
import json
import os
import sys
import datetime
import configparser
import time
import psycopg2
import json
from lib.dateConvert import dateConvert

class moniZdiDB():
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
        currentYear = datetime.datetime.now().year
        date_update = date_update

        cve_re = re.compile(r"CVE\W\w{4}\W\w+")
        url = "https://www.zerodayinitiative.com/advisories/published/"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(url, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        tables = soup.findAll('table')
        selects = soup.findAll('select',{'id':'select-year'})
        options = selects[0].findAll('option')
    
        year_list = []
        for op in options:
            year_list.append(op.text)

        for year in year_list:
                if self.daily:
                    url = "https://www.zerodayinitiative.com/advisories/published/%s/" % currentYear
                else:
                    url = "https://www.zerodayinitiative.com/advisories/published/%s/" % year

                headers = requests.utils.default_headers()
                headers.update({
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                })

                page = requests.get(url, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")

                data = re.findall(r'cases: \[({.*})\]', str(soup))
                try:

                    for d in data[0].split('},'):
                        zdiID = ""
                        title = ""
                        pub_date = ""
                        zdi_can = ""
                        ibase = ""
                        cve_id = ""
                        affected_vendor = ""
                        vuln_name = ''
                        description = ''
                        if re.findall(r'zdiId\': \'(.*?)\',', str(d)):
                            zdiID = re.findall(r'zdiId\': \'(.*?)\',', str(d))[0]
                        if re.findall(r'title\': \'(.*?)\',', str(d)):
                            detailTxt = re.findall(r'title\': \'(.*?)\',', str(d))[0]
                            detailTxt = detailTxt.replace("/", "")
                            detailTxt = detailTxt.replace("()", "")
                            detailTxt = detailTxt.replace("( )", "")
                            detailTxt = detailTxt.replace("'", "")
                            detailTxt = re.sub(r'(\\0)', '', detailTxt)
                            detailTxt = detailTxt.replace("''", "")
                            detailTxt = detailTxt.replace("' '", "")
                            detailTxt = detailTxt.replace("\\0", "\\\\0")
                            detailTxt = detailTxt.replace('"', "'")
                            detailTxt = detailTxt.replace("/", "")
                            detailTxt = re.sub('[^a-zA-Z0-9 \n\.]', '', detailTxt)
                            description = detailTxt
                            vuln_name = detailTxt

                        if re.findall(r'publishDate\': \'(.*?)\',', str(d)):
                            pub_date = re.findall(r'publishDate\': \'(.*?)\',', str(d))[0]
                            try:
                                res1 = dateConvert()
                                pub_date = res1.dateCon(pub_date)
                            except:
                                pass
                        if re.findall(r'zdiCan\': \'(.*?)\',', str(d)):
                            zdi_can = re.findall(r'zdiCan\': \'(.*?)\',', str(d))[0]
                        if re.findall(r'idBase\': (.*?),', str(d)):
                            ibase = re.findall(r'idBase\': (.*?),', str(d))[0]
                        if re.findall(r'cve\': \'(.*?)\',', str(d)):
                            cves = re.findall(r'(CVE-\d+-\d+)', str(d), re.IGNORECASE)
                        if re.findall(r'affectedVendors\': \'(.*?)\'', str(d)):
                            affected_vendor = re.findall(r'affectedVendors\': \'(.*?)\'', str(d))[0]

                        reference = "https://www.zerodayinitiative.com/advisories/%s/" % zdiID

                        details = {}
                        details['affected_vendor'] = affected_vendor
                        details['year'] = year
                        details['zdi_can'] = zdi_can
                        details['ibase'] = ibase

                        for cve_id in cves:
                            cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{zdiID}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(zdiID=zdiID, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='zdi')
                            print(cmd)
                            self.cursor.execute(cmd)
                            self.connection.commit()
                except:
                    pass    
            
                if self.daily:
                    break

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniZdiDB()
    res.initialize(date_update)
