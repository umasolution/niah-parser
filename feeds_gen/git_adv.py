import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import mechanicalsoup
import re
import time
import datetime
import sys
import configparser
import requests
import json
import psycopg2

class git_sync():
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
        self.feedStartYear = self.settings.get('monitor', 'feedStartFrom')

    def getPageSource(self, url):
        html_source = ''
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument('ignore-certificate-errors')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('-no-sandbox')
            driver = webdriver.Chrome('./tool/chromedriver', chrome_options=chrome_options)
            driver.set_page_load_timeout(120)
            driver.set_script_timeout(120)
            driver.get(url)
            html_source = driver.page_source
            driver.close()
        except:
            pass
            
        return html_source
      
    def gitSearch(self, date_update):
        year = datetime.datetime.now().year

        while year >= 2018:
            i = 1
            while True:
                url = "https://github.com/search?q=%%22CVE-%s-%%22" % year
                url = "https://github.com/search?p=%s&q=%%22CVE-%s-%%22&type=Repositories" % (i, year)
                html_source = self.getPageSource(url)
                i = i + 1

                if html_source:
                    soup = BeautifulSoup(html_source, "html.parser")

                if soup.findAll('span', {'class':'next_page disabled'}):
                    break

                for ul in soup.findAll('ul', {'class':'repo-list'}):
                    for li in ul.findAll('li'):
                        liTxt = li.findAll('div', {'class':'f4 text-normal'})[0].text.strip()
                        urlGit = "https://github.com/%s" % liTxt

                        page_source = self.getPageSource(urlGit)
            
                        if re.findall(r'(CVE-\d+-\d+)', str(page_source).encode('ascii', 'ignore').decode('ascii'), re.IGNORECASE):
                            cves = re.findall(r'(CVE-\d+-\d+)', str(page_source), re.IGNORECASE)
                            if re.findall(r'content=\"repository:(\d+)\"\s+', str(page_source)):
                                id = re.findall(r'content=\"repository:(\d+)\"\s+', str(page_source))[0]
                            else:
                                id = ''

                            name = liTxt.split("/")[1]
                            url = urlGit
                            cves = self.getUCVEs(cves)
                            details = {}
                            pub_date = ''
                            for cve in cves:
                                cmd = """INSERT INTO pocreference_db("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{id}', '{cve}', '{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}');""".format(id=id, cve=cve, name=name, details=json.dumps(details), pub_date=pub_date, url=url, date_update=date_update, application='github')
                                print(cmd)
                                self.cursor.execute(cmd)
                                self.connection.commit() 
            year -= 1

    def getUCVEs(self, cves):
        cveLists = []
        for cve in cves:
            if cve not in cveLists:
                cveLists.append(cve)
        return cveLists

    def initialize(self, cve_id, scan=True):
        now = datetime.datetime.now()
        date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
        query = 'SELECT * FROM pocreference_db where cve_id="%s" and application="github"' % cve_id
        self.cursor.execute(query)
        gitdb = self.cursor.fetchall();
        if len(gitdb) == 0 or scan == True:
            gitArray = []
            try:
                r = requests.get("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&access_token=a108736815eeeab0148b70bf24c7b532eacdfd8f" % cve_id)
                data = r.text
                data = json.loads(data)
                totalCount = data["total_count"]
            except:
                try:
                    time.sleep(30)
                    r = requests.get("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&access_token=a108736815eeeab0148b70bf24c7b532eacdfd8f" % cve_id)
                    data = r.text
                    data = json.loads(data)
                    if "rate-limiting" in str(data):
                        time.sleep(60)
                        r = requests.get("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&access_token=a108736815eeeab0148b70bf24c7b532eacdfd8f" % cve_id)
                        data = r.text
                        data = json.loads(data)
                    totalCount = data["total_count"]
                except:
                    totalCount = 0
                    pass

            if totalCount != 0:
                gitHubID =  data['items'][0]['id']
                git_url =  data['items'][0]['html_url']
                git_name =  data['items'][0]['name']
                details = {}
                pub_date = ''

                cmd = """INSERT INTO pocreference_db("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{id}', '{cve}', '{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}');""".format(id=gitHubID, cve=cve_id, name=git_name, details=json.dumps(details), pub_date=pub_date, url=git_url, date_update=date_update, application='github')
                print(cmd)
                self.cursor.execute(cmd)
                self.connection.commit()


if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = git_sync()
    #res.gitSearch(date_update)
    res.initialize('CVE-2020-0022', scan=True)
