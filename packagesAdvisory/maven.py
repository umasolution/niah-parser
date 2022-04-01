from operator import truediv
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from lib.dateConvert import dateConvert
import requests
import re
import json
import psycopg2
import nltk
import os
import sys
import datetime
import configparser
import time
import nltk
import tqdm

class moniMaven():
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
        
    def arrayCheck(self, ver1, verArray):
        for ver in verArray:
            if ver == ver1:
                pass
            elif ver1 > ver:
                return False

        return True

    def uniqArray(self, resArray):
        results = []
        for res in resArray:
            res = res.upper()
            if res not in results:
                results.append(res)

        return results

    def getPageSource_org(self, url):
        html_source = ''
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('ignore-certificate-errors')
            driver = webdriver.Chrome('./tool/chromedriver', chrome_options=chrome_options)

            driver.set_page_load_timeout(120)
            driver.set_script_timeout(120)
            driver.get(url)
            html_source = driver.page_source
            driver.close()
            return html_source
        except:
            return html_source

    def getPageSource(self, url):
        response = requests.get(url)
        return response.text


    def getPageDetails(self, url):
        try:
            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
            return str(soup)
        except:
            soup = ''
            return soup


    def initialize(self, date_update):
        url = "https://repo1.maven.org/maven2/"
        
        temp_arr = []

        
        # level-1
        urls = {}
        urls['urls'] = []
        
        page_src = self.getPageSource(url)
        soup = BeautifulSoup(page_src, "html.parser")
        for a_tag in soup.findAll('a'):
            if re.findall(r'(\w+\/)', str(a_tag.text)):
                tagname = re.sub(r'/', '', str(a_tag.text))
                url_one = "https://repo1.maven.org/maven2/%s" % tagname
                urls['urls'].append(url_one)

        out_data = open("maven/level-1.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-1 completed")
        """

        # level-2
        with open("maven/level-1.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)


        out_data = open("maven/level-2.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-2 completed")
        
        # level-3
        with open("maven/level-2.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)

        out_data = open("maven/level-3.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-3 completed")
        
        # level-4
        with open("maven/level-3.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)

        out_data = open("maven/level-4.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-4 completed")

        # level-5
        with open("maven/level-4.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)

        out_data = open("maven/level-5.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-5 completed")

        # level-6
        with open("maven/level-5.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)

        out_data = open("maven/level-6.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-6 completed")


        # level-7
        with open("maven/level-6.json", "r") as f:
            out_data = json.load(f)

        with open("maven/temp_arr.json", "r") as f:
            temp_arr = json.load(f)

        urls = {}
        urls['urls'] = []
        for url in out_data['urls']:
            if url not in temp_arr:
                page_src = self.getPageSource(url)
                soup = BeautifulSoup(page_src, "html.parser")

                for a_tag in soup.findAll('a'):
                    if re.findall(r'(\w+\/)', str(a_tag.text)):
                        tagname = re.sub(r'/', '', str(a_tag.text))
                        url_one = "%s/%s" % (url, tagname)
                        
                        page_src = self.getPageSource(url_one)
                        soup = BeautifulSoup(page_src, "html.parser")
                        if self.is_metadata_in(soup.findAll('a')):
                            self.collectdb_json(url_one, tagname)
                        else:
                            urls['urls'].append(url_one)

                temp_arr.append(url)
                out_data = open("maven/temp_arr.json", "w")
                json.dump(temp_arr, out_data, indent=2)

        out_data = open("maven/level-6.json", "w")
        json.dump(urls, out_data, indent=2)
        print("[ OK ] Level-7 completed")
        """


    def collectdb_json(self, url_one, tagname):
        metadata = {}
        url = "%s/maven-metadata.xml" % (url_one)
        print(url)
        versions = self.get_json_metadata_json(url)
        metadata['versions'] = {}

        if versions['latest']:
            url = "%s/%s/%s-%s.pom" % (url_one, versions['latest'], tagname, versions['latest'])
            data = self.get_json_xml(url)
            metadata['versions'][versions['latest']] = data

            for version in versions['all']:
                url = "%s/%s/%s-%s.pom" % (url_one, version, tagname, version)
                data = self.get_json_xml(url)
                metadata['versions'][version] = data

        else:
            if len(versions['all']) > 0:
                url = "%s/%s/%s-%s.pom" % (url_one, versions['all'][0], tagname, versions['all'][0])
                data = self.get_json_xml(url)
                metadata['versions'][versions['latest']] = data
                                
        out_data_2 = open("maven/%s.json" % (tagname), "w")
        json.dump(metadata, out_data_2, indent=2)
      

    def get_json_metadata_json(self, url):
        page_src = self.getPageSource(url)
        print(page_src)
        xml_parser = BeautifulSoup(page_src, "xml")
        
        versions_lists = xml_parser.find_all('version')
        print(versions_lists)
        if xml_parser.find('latest'):
            latest_version = xml_parser.find('latest').contents[0]
            print(latest_version)
        else:
            latest_version = ''

        versions = {}
        versions['latest'] = latest_version
        versions['all'] = []

        for vers in versions_lists:
            version = vers.text
            versions['all'].append(version)

        print(versions)
        return versions


    def get_json_xml(self, url):
        print(url)
        page_src = self.getPageSource(url)
        xml_parser = BeautifulSoup(page_src, "xml")

        results = {}

        if xml_parser.find('groupId'):
            groupid = xml_parser.find('groupId').contents[0]
            results['groupid'] = groupid
        
        if xml_parser.find('artifactId'):
            artifactId = xml_parser.find('artifactId').contents[0]
            results['artifactId'] = artifactId
        try:
            if xml_parser.find('description'):
                description = xml_parser.find('description').contents[0]
                results['description'] = description
        except:
            results['description'] = ''
        if xml_parser.find('name'):
            name = xml_parser.find('name').contents[0]
            results['name'] = name
        if xml_parser.find('packaging'):
            packaging = xml_parser.find('packaging').contents[0]
            results['packaging'] = packaging
        if xml_parser.find('version'):
            version = xml_parser.find('version').contents[0]
            results['version'] = version
        try:
            if xml_parser.find('url'):
                url_src = xml_parser.find('url').contents[0]
                results['url_src'] = url_src
        except:
            results['url_src'] = ''
        if xml_parser.find('modelVersion'):
            modelVersion = xml_parser.find('modelVersion').contents[0]
            results['modelVersion'] = modelVersion
        if xml_parser.find('license'):
            licenses = xml_parser.find('license')
            results['license'] = {}
            if licenses.find('name'):
                results['license']['name'] = licenses.find('name').text
            if licenses.find('url'):
                results['license']['url'] = licenses.find('url').text

        dependencies = []
        if xml_parser.find_all('dependency'):
            dependency = xml_parser.find_all('dependency')
            
            for dep in dependency:
                res = {}
                if dep.find('groupId'):
                    res['groupId'] = dep.find('groupId').text
                if dep.find('artifactId'):
                    res['artifactId'] = dep.find('artifactId').text
                if dep.find('version'):
                    res['version'] = dep.find('version').text
                dependencies.append(res)

        results['dependencies'] = dependencies

        if xml_parser.find('scm'):
            scm = xml_parser.find('scm')
            results['scm'] = {}
            if scm.find('url'):
                results['scm']['url'] = scm.find('url').text.strip()
            if scm.find('connection'):
                results['scm']['connection'] = scm.find('connection').text.strip()
            if scm.find('developerConnection'):
                results['scm']['developerConnection'] = scm.find('developerConnection').text.strip()

        return results
    
    def is_metadata_in(self, atags):
        for atag in atags:
            if atag.text == "maven-metadata.xml":
                return True

        return False  

        
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniMaven()
    res.initialize(date_update)
    #res.get_json_xml('https://repo1.maven.org/maven2/code/google/com/mgnlgroovy-scheduler/1.0.3/mgnlgroovy-scheduler-1.0.3.pom')