from bs4 import BeautifulSoup
import requests
import re
import json
import os
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import configparser
import time
import datetime
from lib.dateConvert import dateConvert
import psycopg2
import json

class moniChromiumDB():
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
        
    def getToken(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('ignore-certificate-errors')
        driver = webdriver.Chrome('./tool/chromedriver', chrome_options=chrome_options)
        driver.set_page_load_timeout(120)
        driver.set_script_timeout(120)
        driver.get("https://bugs.chromium.org/p/project-zero/issues/list?q=&can=1&start=0")
        time.sleep(5)
        html_source = driver.page_source
        return html_source
        driver.close()

    def getCVE(self, ch_id):
        cve_re = re.compile(r"CVE\W\w{4}\W\w+")

        cookies = {
            '_ga': 'GA1.3.1020506650.1554921059',
            '_gid': 'GA1.3.2053930569.1556318656',
            '__utma': '221884874.1042096179.1556319535.1556319535.1556319535.1',
            '__utmc': '221884874',
            '__utmz': '221884874.1556319535.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)',
            'SACSID': '~AJKiYcHyRO5R2z5yxy4XAlkYtKON0tqhhb1Pe6fnHIoSpyJ9mMYxiUAepWpMd76AGc1y0kdYUReBAB2R-UZ77Rcxw7tQ4ZbZnIaVQh5hd00k2NzYg8ffkpmYMk0GCif4jFzTHmUpnZUJx38Di3g_kmG2xfUrh7S_etlcyXO6VtwRLPWmjxvdRCuXl1jNPGgk06Yl5P5m4FFAtdukCkKSq6Gqb0-F2cQrIG0LM37nEmOT9pHmjTSv-V0xan9LLUyWRHlgUlEgPtz9hp72BN-vpoyeKRhMJAcnUBhTz2wuCtvzuS75ix_DLNqh4a4DJUnKY1Sv9Wnuu5Jo',
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.5',
            'content-type': 'application/json',
            'X-Xsrf-Token': '8PnwEpNIA8CkSxjYg7G3UDoxNjE1Nzc5NDUw',
            'Origin': 'https://bugs.chromium.org',
            'Connection': 'keep-alive',
            'TE': 'Trailers',
        }
        data = '{"issueRef":{"localId":%s,"projectName":"project-zero"}}' % ch_id
        response = requests.post('https://bugs.chromium.org/prpc/monorail.Issues/GetIssue', headers=headers, cookies=cookies, data=data)

        data = response.text

        if re.findall(cve_re, str(data)):
            return re.findall(cve_re, str(data))[0]
        else:
            return None

    def initialize(self, date_update):
        date_update = date_update
        html_source = self.getToken()
        if re.findall(r'\'token\': \'(.*)\',', str(html_source)):
            token = re.findall(r'\'token\': \'(.*)\',', str(html_source))[0]
        else:
            token = ''

        i = 1
        while True:
            check = True
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.5',
                'content-type': 'application/json',
                'X-Xsrf-Token': '%s' % token,
                'Origin': 'https://bugs.chromium.org',
                'Connection': 'keep-alive',
                'TE': 'Trailers',
            }
            cookies = {
                '_ga': 'GA1.3.1020506650.1554921059',
                '_gid': 'GA1.3.2053930569.1556318656',
                '__utma': '221884874.1042096179.1556319535.1556319535.1556319535.1',
                '__utmc': '221884874',
                '__utmz': '221884874.1556319535.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)',
                'SACSID': '~AJKiYcFmrJDs0I97N0dIT26EFRuNCIQj4VPZWKxZCPr6_6Cts-Cm3c6E4IPPwUftQO_OMKF3bM1i9hYYBNSNaLCxvz6ERx4s-uL4fVrNxgggsv2hMkw0Pn_84KE6YMYqZqVitfeBFzUs5_wp_AV3ezexWjXsX7d-gkAYwmhjkDFCzHZFGd-Rrz2D-UnJ4GuzJsZCNxZbfC-elHlPbsUURBLxDhvr_okCKjg7L9j_OzCc8Om_uU-LQwdD0eioFih8WswMIHbs5y6nwLRhK2LJavnsmb_HeKNlhjBWIiBs2FroS0zD_DgdO05ihKoRVhjW_iHIyiLXpIaSqcIEphv5wQZcsj6-HZpM1g',
            }
            data = '{"projectNames":["project-zero"],"query":"","cannedQuery":1,"pagination":{"start":%s,"maxItems":100}}' % (i)
            response = requests.post('https://bugs.chromium.org/prpc/monorail.Issues/ListIssues', headers=headers, cookies=cookies, data=data)
            resText = response.text
             
            with open("/tmp/t.txt", "w") as f:
                f.write(resText)

            with open("/tmp/t.txt") as f:
                content = f.readlines()
                content = content[1:]
                with open("/tmp/t1.txt", "w") as f:
                    f.write(''.join(content))

            with open("/tmp/t1.txt", "r") as jsonTxt:
                resJson = json.load(jsonTxt)

            if 'issues' not in resJson:
                break
            
            if check:
                for issue in resJson['issues']:
                    cve_id = ''
                    severity = ''
                    vendor = ''
                    product = ''
                    pub_date = ''
                    status = issue['statusRef']['status']
                    chromium_id = issue['localId']
                    description1 = issue['summary']
                    description = description1.replace("'", "")
                    vuln_name1 = description1
                    vuln_name = vuln_name1.replace("'", "")
                    if 'labelRefs' in issue:
                        for lbl in issue['labelRefs']:
                            if "CVE-" in lbl['label'] or "cve-" in lbl['label']:
                                cve_id = lbl['label']
                            if "Vendor-" in lbl['label'] or "vendor-" in lbl['label']:
                                vendor = lbl['label']
                                vendor = re.sub(r'Vendor-', '', str(vendor), re.IGNORECASE)
                            if "Product-" in lbl['label'] or "product-" in lbl['label']:
                                product = lbl['label']
                                product = re.sub(r'Product-', '', str(product), re.IGNORECASE)
                            if "Severity-" in lbl['label'] or "severity-" in lbl['label']:
                                severity = lbl['label']
                                severity = re.sub(r'Severity-', '', str(severity), re.IGNORECASE)
                            if "Reported-" in lbl['label'] or "reported-" in lbl['label']:
                                pub_date = lbl['label']
                                pub_date = re.sub(r'Reported-', '', str(pub_date), re.IGNORECASE)
                                res1 = dateConvert() 
                                pub_date = res1.dateCon(pub_date)

                    url = "https://bugs.chromium.org/p/project-zero/issues/detail?id=%s" % chromium_id
                    reference = url
                    details = {}
                    details['severity'] = severity
                    details['product'] = product
                    details['vendor'] = vendor
                    details['status'] = status
                
                    if cve_id:
                        try:
                            cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{chromium_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(chromium_id=chromium_id, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='chromium')
                            print(cmd)
                            self.cursor.execute(cmd)
                            self.connection.commit()
                        except:
                            pass
            i = i + 100

            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniChromiumDB()
    res.initialize(date_update)
