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
import psycopg2
import json

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

    def getPageSource(self, url):
        html_source = ''
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
        return html_source


    def gitSearch(self, date_update):
        year = datetime.datetime.now().year

        while year >= 2002:
            i = 1
            while True:
                url = "https://github.com/search?q=%%22CVE-%s-%%22" % year
                url = "https://github.com/search?p=%s&q=%%22CVE-%s-%%22&type=Repositories" % (i, year)
                html_source = self.getPageSource(url)
                soup = BeautifulSoup(html_source, "html.parser")

                i = i + 1

                if self.daily:
                    if i == 3:
                        break

                if soup.findAll('span', {'class':'next_page disabled'}):
                    break

                for ul in soup.findAll('ul', {'class':'repo-list'}):
                    for li in ul.findAll('li'):
                        liTxt = li.findAll('div', {'class':'f4 text-normal'})[0].text.strip()
                        urlGit = "https://github.com/%s" % liTxt

                        page_source = self.getPageSource(urlGit)
                        page_source = page_source.encode('ascii', 'ignore').decode('ascii')
            
                        if re.findall(r'(CVE-\d+-\d+)', str(page_source), re.IGNORECASE):
                            cves = re.findall(r'(CVE-\d+-\d+)', str(page_source), re.IGNORECASE)
                        if re.findall(r'content=\"repository:(\d+)\"\s+', str(page_source)):
                            id = re.findall(r'content=\"repository:(\d+)\"\s+', str(page_source))[0]
                        else:
                            id = ''

                        name1 = liTxt.split("/")[1]
                        name = name1.replace("'", "")
                        url1 = urlGit
                        url = url1.replace("'", "")
                        cves = self.getUCVEs(cves)
                        pub_date = ''
                        details = {}
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


    def isGitID(self, git_id, cve_id):
        cmd = 'select * from PoCReference_DB where app_id = "%s" and cve_id="%s"' % (git_id, cve_id)
        cur = self.mydb.cursor()
        cur.execute(cmd)
        if len(cur.fetchall()) == 0:
            return True
        else:
            return False


if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = git_sync()
    res.gitSearch(date_update)
