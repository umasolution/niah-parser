from bs4 import BeautifulSoup
import requests
import re
import nltk
import os
import sys
import configparser
import datetime
import psycopg2
import json
from lib.dateConvert import dateConvert

class moniVulnDB():
    def __init__(self):
        self.vulnCatLists = ['webapp', 'vendor', 'remote', 'local']
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        hostName = self.settings.get('database', 'host')
        userName = self.settings.get('database', 'user')
        password = self.settings.get('database', 'pass')
        databaseName = self.settings.get('database', 'dbname')
        self.connection = psycopg2.connect(user=userName,password=password,host=hostName,port="5432",database=databaseName)
        self.cursor = self.connection.cursor()   
        

    def getProducts(self, soup):
        tokens = nltk.word_tokenize(soup.decode('utf-8'))
        text1 = ' '.join(tokens)
        if re.findall(r'Affected Product \( s \) : =+ (.*) Exploitation Technique', text1): 
            return re.findall(r'Affected Product \( s \) : =+ (.*) Exploitation Technique', text1)[0]
        else:
            return "None"

    def getClass(self, soup):
        tokens = nltk.word_tokenize(soup.decode('utf-8'))
        text1 = ' '.join(tokens)
        if re.findall(r'Vulnerability Class : =+ (.*) Current', text1):
            return re.findall(r'Vulnerability Class : =+ (.*) Current', text1)[0]
        else:
            return "None"

    def initialize(self, date_update):
        date_update = date_update

        for vulnCat in self.vulnCatLists:
            check = True
            cookies = {
                'PHPSESSID': '5g1mj1kvkr67movv8lt90o1be5',
            }

            headers = {
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Accept-Language': 'en-US,en;q=0.9',
            }

            params = (
                ('cat', '%s' % vulnCat),
            )

            try:
                html = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params, cookies=cookies)
            except:
                try:
                    time.sleep(120)	
                    html = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params, cookies=cookies)
                except:
                    print("Error")
                    check = False
                
            if check:
                soup = BeautifulSoup(html.text, "html.parser")
                cve_re = re.compile(r"CVE\W\w{4}\W\w+")
                res_Array = []

                links = soup.findAll('div',{'class':'Stil8'})
                aTags = links[0].findAll('a')
                aList = []
                aList.append("1")
                for a in aTags:
                    aList.append(str(a.text))

                for aNo in aList:
                    check1 = True
                    params = (
                        ('cat', '%s' % vulnCat),
                    )

                    params1 = (
                        ('page', '%s' % aNo),
                        ('cat', '%s' % vulnCat),
                    )

                    try:
                        if self.daily:
                            html1 = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params, cookies=cookies)
                        else:
                            html1 = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params1, cookies=cookies)
                    except:
                        try:
                            time.sleep(60)
                            if self.daily:
                                html1 = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params, cookies=cookies)
                            else:
                                html1 = requests.get('https://www.vulnerability-lab.com/show.php', headers=headers, params=params1, cookies=cookies)
                        except:
                            print("Error")
                            check1 = False

                    if check1:
                        soup = BeautifulSoup(html1.text, "html.parser")
                        trLists = soup.findAll('tr',{'class':'submit'})
            
                        for tr in trLists:
                            tdLists = tr.findAll('td')
                            i = 1
                            type = ""
                            desc = ""
                            vul_id = ""
                            cves = ""
                            type = ""
                            url = ""
                            reference = ''
                            pub_date = ""
                            vuln_class = ""
                            product = ""
                            for td in tdLists:
                                if i == 2:
                                    pub_date = td.text
                                    try:
                                        res1 = dateConvert()
                                        pub_date = res1.dateCon(pub_date)
                                    except:
                                        pass
                    
                                if i == 6:
                                    type = td.text
                                if i == 4:
                                    check2 = True
                                    desc = td.text
                                    description = desc
                                    vuln_name = desc
                                    params2 = (
                                        ('id', '2121'),
                                    )

                                    try:
                                        html4 = requests.get('https://www.vulnerability-lab.com/get_content.php', headers=headers, params=params2, cookies=cookies)
                                    except:
                                        try:
                                            time.sleep(60)
                                            html4 = requests.get('https://www.vulnerability-lab.com/get_content.php', headers=headers, params=params2, cookies=cookies)
                                        except:
                                            check2 = False
                                            pass

                                    if check2:		
                                        url = "https://www.vulnerability-lab.com/%s" % td.findAll('a')[0]['href']
                                        reference = url
                                        vul_id = re.findall(r'\?id=(\d+)', str(url))[0]
                                        soup = BeautifulSoup(html4.text, "html.parser")

                                        if re.findall(r'Affected Product', str(soup)):
                                            product = self.getProducts(soup)
                                        else:
                                            product = "Unknown"

                                        if re.findall(r'Affected Product', str(soup)):
                                            vuln_class = self.getClass(soup)
                                        else:
                                            vuln_class = "Unknown"

                                        if re.findall(cve_re, str(soup)):
                                            cves = re.findall(cve_re, str(soup))
                                        else:
                                            cves = ""

                                        if re.findall(r'Proof of Concept', str(soup)):
                                            poc = url
                                        else:
                                            poc = "no"

                                i = i + 1

                            details = {}
                            details['poc'] = poc
                            details['product'] = product
                            details['type'] = type
                            details['vulnCat'] = vulnCat
            
                            for cve_id in cves:
                                cmd = """INSERT INTO PoCReference_DB("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{vul_id}', '{cve_id}', '{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{description}', '{vuln_name}', '{details}', '{pub_date}', '{reference}', '{date_update}');""".format(vul_id=vul_id, cve_id=cve_id, description=description, details=json.dumps(details), vuln_name=vuln_name, pub_date=pub_date, reference=reference, date_update=date_update, application='vulnerability-lab')
                                try:
                                    print(cmd)
                                except:
                                    pass
                                self.cursor.execute(cmd)
                                self.connection.commit()

                    if self.daily:
                        break

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniVulnDB()
    res.initialize(date_update)
