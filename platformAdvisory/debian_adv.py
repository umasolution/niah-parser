from bs4 import BeautifulSoup
import xmltodict
import sqlite3
import requests
import re
import os
import sys
import configparser
import time
import datetime
import psycopg2
import json
from tqdm import tqdm
from lib.alearts_manage import check_alerts
from lib.dateConvert import dateConvert

class moniDebianDB():
    def __init__(self):
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        self.hostName = self.settings.get('database', 'host')
        self.userName = self.settings.get('database', 'user')
        self.password = self.settings.get('database', 'pass')
        self.databaseName = self.settings.get('database', 'dbname')

        self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
        self.cursor = self.connection.cursor()   
        
        sys.setrecursionlimit(100000)

        query = "select niahid, revision, lastmodifieddate from vuln_tab ORDER BY revision DESC;"
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        self.niahid_entry = {}

        for data in fetchData:
            niahid = data[0]
            revision = data[1]
            lastmodifieddate = data[2]

            if niahid not in self.niahid_entry:
                self.niahid_entry[niahid] = {}
                self.niahid_entry[niahid]['revision'] = revision
                self.niahid_entry[niahid]['lastmodifieddate'] = lastmodifieddate

        query = "select niah_product_id, revision from product_reference_tab ORDER BY revision DESC;"
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        self.product_entry = {}

        for data in fetchData:
            niah_product_id = data[0]
            revision = data[1]

            if niah_product_id not in self.product_entry:
                self.product_entry[niah_product_id] = revision


        query = "select niah_version_id, revision from affected_versions_tab ORDER BY revision DESC;"            
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        self.versions_entry = {}

        for data in fetchData:
            niah_version_id = data[0]
            revision = data[1]

            if niah_version_id not in self.versions_entry:
                self.versions_entry[niah_version_id] = revision

    
    def getBinaries(self, product, platform):
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        url = "https://packages.debian.org/source/%s/%s" % (platform, product)
        try:
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
        except:
            print("Timee sleep")
            time.sleep(240)
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")

        rPackages = []
        for div in soup.findAll('div', {'id':'pbinaries'}):
            for aTag in div.findAll('a'):
                product = aTag.text
                rPackages.append(str(product))

        return rPackages

    def check_niahid_entry(self, niahId):
        self.connection = psycopg2.connect(user='versa',password='versa123',host='127.0.0.1',port="5432",database='niahdb')
        self.cursor = self.connection.cursor()
        query = "select cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, revision from vuln_tab where niahid='%s'" % niahId
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            return fetchData
        else:
            return False

    def getrss(self, date_update):
        print("RSS Fetch Started")
        cve_re = re.compile(r"CVE\W\w{4}\W\w+")
        url = "https://www.debian.org/security/dsa"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
        })

        page = requests.get(url, headers=headers)
        results = xmltodict.parse(page.content)
        for item in tqdm(results['rdf:RDF']['item']):
            name = item['title']
            link = item['link']
            year = re.findall(r'security\/(\d+)\/dsa-\d+$', str(link))[0]	

            aTag = re.findall(r'\/(dsa-\d+)$', str(link))[0]
            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })

            try:
                page = requests.get(link, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")
            except:
                time.sleep(120)
                page = requests.get(link, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")

            soup = soup.encode("utf-8")

            if re.findall(r'<dd>(.* \d\d\d\d)<\/dd>', str(soup)):
                pub_date = re.findall(r'<dd>(.* \d\d\d\d)<\/dd>', str(soup))[0]
                pub_date = pub_date.strip()
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:
                    pass  
            else:
                pub_date = ""

            if re.findall(cve_re, str(soup)):
                cves = re.findall(r'CVE-\d+-\d+', str(soup), re.IGNORECASE)
            else:
                cves = []

            if len(cves) > 0:
                for cve in list(set(cves)):
                    niahId = "NIAH-CVE-%s" % (cve)
                    publisheddate = pub_date
                    lastmodifieddate = pub_date
                    data_type = 'CVE'
                    data_id = cve

                    niah_version_id = "NIAH-VERSION-PLATFORM-DEBIAN-%s" % (cve)

                    check = True

                    url1 = "https://security-tracker.debian.org/tracker/%s" % cve
                    reference = url1

                    cwe_id = {}
                    cwe_id['data'] = []

                    refe = {}
                    refe['data'] = []
                    refe['data'].append(reference)

                    basemetricv2_data = {}
                    basemetricv3_data = {}

                    
                    headers = requests.utils.default_headers()
                    headers.update({
                        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                    })

                    try:
                        page = requests.get(url1, headers=headers)
                        soup = BeautifulSoup(page.content, "html.parser")
                    except:
                        try:
                            time.sleep(340)
                            page = requests.get(url1, headers=headers)
                            soup = BeautifulSoup(page.content, "html.parser")
                        except:
                            check = False
                            pass

                    tables = soup.findAll('table')
                    
                    desc = "" 
                    productVersions = []
                    productName = ""
                    platform = ""
                    version = ""
                    productVersion = {}
                    productVersion['details'] = []

                    if check:
                        for table in tables:
                            if re.findall(cve_re, str(table)):
                                i = 1
                                for tr in table.findAll('tr'):
                                    if i == 2:
                                        j = 1
                                        for td in tr.findAll('td'):
                                            if j == 2:
                                                desc = td.text
                                                desc = re.sub('[^a-zA-Z0-9 \n\.]', '', desc)
                                            j = j + 1
                                    i = i + 1
                            
                            if re.findall(r'Fixed Version', str(table)):
                                i = 1
                                for tr in table.findAll('tr'):
                                    productName = ''
                                    platform = ''
                                    version = ''
                                    res = {}
                                    if i != 1:
                                        j = 1
                                        for td in tr.findAll('td'):
                                            if j == 1:
                                                productName = td.text
                                                res['product'] = str(productName)
                                            if j == 3:
                                                platform = td.text
                                                platform = platform.replace("(", "")
                                                platform = platform.replace(")", "")
                                                res['platform'] = str(platform.strip())
                                            if j == 4:
                                                version = td.text
                                                version = version.replace("(", "")
                                                version = version.replace(")", "")
                                                res['version'] = str(version.strip())
                                            j = j + 1

                                    if productName and platform and version:
                                        #relatedPackages = self.getBinaries(productName, platform)
                                        #res['relatedPackages'] = relatedPackages
                                        productVersion['details'].append(res)

                                    i = i + 1	

                    results = {}

                    if len(productVersion['details']) > 0:
                        
                        desc = desc.replace("'", "")
                        name = name.replace("'", "")

                        desc = {}
                        desc['debian'] = name


                        for det in productVersion['details']:
                            product = det['product']
                            product = product.lower()
                            platform = det['platform']
                            #relatedPackages = det['relatedPackages']

                            if 'versions' in det:
                                versions = det['versions']
                            if 'version' in det:
                                versions = det['version']


                            niah_product_id = "NIAH-PLATFORM-DEBIAN-%s" % (product)
                            

                            res = {}
                            res['platform'] = 'linux'
                            res['os'] = 'debian'
                            
                            vendor = ''
                            advisory = 'debian'
                            type = 'platform'

                            if niah_product_id not in self.product_entry:
                                self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                self.cursor = self.connection.cursor()

                                query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '0')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res))
                                self.cursor.execute(query)
                                self.connection.commit()

                                self.product_entry[niah_product_id] = '0'

                                query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
                                self.cursor.execute(query)
                                self.connection.commit()


                            res = {}
                            res['product'] = product
                            res['versions'] = versions
                            res['platform'] = platform
                            res['advisoryid'] = aTag
                            res['patch'] = "upgrade to %s" % versions
        
                            if niah_product_id not in results:
                                results[niah_product_id] = []

                            if res not in results[niah_product_id]:
                                results[niah_product_id].append(res)

                        check = True

                        affected_products_versions = []
                        affected_products_versions.append(niah_version_id)

                        if niahId in self.niahid_entry:
                            revision = int(self.niahid_entry[niahId]['revision']) + 1
                            if lastmodifieddate == self.niahid_entry[niahId]['lastmodifieddate']:
                                check = False

                            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastmodifieddate

                            fetchData = self.check_niahid_entry(niahId)
                            if fetchData:
                                affected_products_versions_old = fetchData[0][7]
                                for affected_version_nu in affected_products_versions_old:
                                    if affected_version_nu not in affected_products_versions:
                                        affected_products_versions.append(affected_version_nu)
                        else:
                            revision = '0'
                            self.niahid_entry[niahId] = {}
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastmodifieddate
                            self.niahid_entry[niahId]['revision'] = '0'


                        self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                        self.cursor = self.connection.cursor()
                        if check:
                            self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            try:
                                query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV2}', '{baseMetricV3}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                self.cursor.execute(query)
                                self.connection.commit()
                            except:
                                try:
                                    desc = {}
                                    query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV2}', '{baseMetricV3}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                    self.cursor.execute(query)
                                    self.connection.commit()        
                                except:
                                    pass

                            
                            self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            self.cursor.execute(query)
                            self.connection.commit()
                            
                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = int(self.versions_entry[niah_version_id]) + 1
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision
                                
                            self.versions_entry[niah_version_id] = revision
                            
                            self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results), revision)
                            self.cursor.execute(query)
                            self.connection.commit()

                            message = "(NIAH-VULN-ID : %s) %s CVE updated for Ubuntu Platform" % (niahId, data_id)
                            res = check_alerts()
                            res.update_alerts('cve_id', data_id, lastmodifieddate, message)
                            

    def initialize(self, date_update):
        self.getrss(date_update)
        date_update = date_update
        cve_re = re.compile(r"CVE\W\w{4}\W\w+")
        url = "https://www.debian.org/security/"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        try:
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
        except:
            print("Timee sleep")
            time.sleep(120)
            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")
    
        years = re.findall(r'href=\"(\d+)\/\">', str(soup))

        for year in years:
            if int(year) >= 1998:
                print(year)
                if self.daily:  
                    url = "https://www.debian.org/security"
                    headers = requests.utils.default_headers()
                    headers.update({
                        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                    })
                else:
                    url = "https://www.debian.org/security/%s/" % year
                    headers = requests.utils.default_headers()
                    headers.update({
                        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                    })

                try:
                    page = requests.get(url, headers=headers)
                    soup = BeautifulSoup(page.content, "html.parser")
                except:
                    time.sleep(120)
                    page = requests.get(url, headers=headers)
                    soup = BeautifulSoup(page.content, "html.parser")

        
                vulLinks = soup.findAll('strong')

                for vlink in tqdm(vulLinks):
                    if re.findall(r'DSA-', str(vlink)):
                        name = ""
                        aTag = ""
                        name = vlink.findAll('a')[0].text
                        aTag = vlink.findAll('a')[0].get('href')
                        aTag = aTag.replace('./', '')

                        if re.findall(r'(dsa-\d+)', str(aTag)):
                            aTag = re.findall(r'(dsa-\d+)', str(aTag))[0]
                
                        if self.daily:
                            urlSub = "https://www.debian.org/security/%s" % (aTag)
                        else:
                            urlSub = "https://www.debian.org/security/%s/%s" % (year, aTag)

                        headers = requests.utils.default_headers()
                        headers.update({
                            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                        })

                        try:
                            page = requests.get(urlSub, headers=headers)
                            soup = BeautifulSoup(page.content, "html.parser")
                        except:
                            time.sleep(120)
                            page = requests.get(urlSub, headers=headers)
                            soup = BeautifulSoup(page.content, "html.parser")

                        soup = soup.encode("utf-8")

                        if re.findall(r'<dd>(.* \d\d\d\d)<\/dd>', str(soup)):
                            pub_date = re.findall(r'<dd>(.* \d\d\d\d)<\/dd>', str(soup))[0]
                            pub_date = pub_date.strip()
                            try:
                                res1 = dateConvert()
                                pub_date = res1.dateCon(pub_date)
                            except:
                                pass
                    
                        else:
                            pub_date = ""

                        if re.findall(cve_re, str(soup)):
                            #cves = re.findall(cve_re, str(soup))
                            cves = re.findall(r'CVE-\d+-\d+', str(soup), re.IGNORECASE)
                        else:
                            cves = []



                        if len(cves) > 0:
                            for cve in list(set(cves)):
                                check = True
                                niahId = "NIAH-CVE-%s" % (cve)
                                publisheddate = pub_date
                                lastmodifieddate = pub_date
                                data_type = 'CVE'
                                data_id = cve

                                niah_version_id = "NIAH-VERSION-PLATFORM-DEBIAN-%s" % (cve)

                                check = True

                                url1 = "https://security-tracker.debian.org/tracker/%s" % cve
                                reference = url1

                                cwe_id = {}
                                cwe_id['data'] = []

                                refe = {}
                                refe['data'] = []
                                refe['data'].append(reference)

                                basemetricv2_data = {}
                                basemetricv3_data = {}

                                headers = requests.utils.default_headers()
                                headers.update({
                                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                                })

                                try:
                                    page = requests.get(url1, headers=headers)
                                    soup = BeautifulSoup(page.content, "html.parser")
                                except:
                                    try:
                                        time.sleep(340)
                                        page = requests.get(url1, headers=headers)
                                        soup = BeautifulSoup(page.content, "html.parser")
                                    except:
                                        check = False
                                        pass

                                tables = soup.findAll('table')
                    
                                desc = "" 
                                productVersions = []
                                productName = ""
                                platform = ""
                                version = ""
                                productVersion = {}
                                productVersion['details'] = []

                                if check:
                                    for table in tables:
                                        if re.findall(cve_re, str(table)):
                                            i = 1
                                            for tr in table.findAll('tr'):
                                                if i == 2:
                                                    j = 1
                                                    for td in tr.findAll('td'):
                                                        if j == 2:
                                                            desc = td.text
                                                            desc = re.sub('[^a-zA-Z0-9 \n\.]', '', desc)
                                                        j = j + 1
                                                i = i + 1
                            
                                        if re.findall(r'Fixed Version', str(table)):
                                            i = 1
                                            for tr in table.findAll('tr'):
                                                productName = ''
                                                platform = ''
                                                version = ''
                                                res = {}
                                                if i != 1:
                                                    j = 1
                                                    for td in tr.findAll('td'):
                                                        if j == 1:
                                                            productName = td.text
                                                            res['product'] = str(productName)
                                                        if j == 3:
                                                            platform = td.text
                                                            platform = platform.replace("(", "")
                                                            platform = platform.replace(")", "")
                                                            res['platform'] = str(platform.strip())
                                                        if j == 4:
                                                            version = td.text
                                                            version = version.replace("(", "")
                                                            version = version.replace(")", "")
                                                            res['version'] = str(version.strip())
                                                        j = j + 1

                                                if productName and platform and version:
                                                    #relatedPackages = self.getBinaries(productName, platform)
                                                    #res['relatedPackages'] = relatedPackages
                                                    productVersion['details'].append(res)

                                                i = i + 1	

                                results = {}

                                if len(productVersion['details'] ) > 0:
                                    desc = desc.replace("'", "")
                                    name = name.replace("'", "")

                                    desc = {}
                                    desc['debian'] = name


                                    for det in productVersion['details']:
                                        product = det['product']
                                        product = product.lower()
                                        platform = det['platform']
                                        #relatedPackages = det['relatedPackages']

                                        if 'versions' in det:
                                            versions = det['versions']
                                        if 'version' in det:
                                            versions = det['version']


                                        niah_product_id = "NIAH-PLATFORM-DEBIAN-%s" % (product)
                                        

                                        res = {}
                                        res['platform'] = 'linux'
                                        res['os'] = 'debian'
                                        
                                        vendor = ''
                                        advisory = 'debian'
                                        type = 'platform'


                                        if niah_product_id not in self.product_entry:
                                            self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                            self.cursor = self.connection.cursor()

                                            query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '0')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res))
                                            self.cursor.execute(query)
                                            self.connection.commit()
                                            self.product_entry[niah_product_id] = '0'

                                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
                                            self.cursor.execute(query)
                                            self.connection.commit()

                                        res = {}
                                        res['product'] = product
                                        res['versions'] = versions
                                        res['platform'] = platform
                                        res['advisoryid'] = aTag
                                        res['patch'] = "upgrade to %s" % versions
                    
                                        if niah_product_id not in results:
                                            results[niah_product_id] = []

                                        if res not in results[niah_product_id]:
                                            results[niah_product_id].append(res)


                                    check = True
                                    affected_products_versions = []
                                    affected_products_versions.append(niah_version_id)

                                    if niahId in self.niahid_entry:
                                        revision = int(self.niahid_entry[niahId]['revision']) + 1
                                        if lastmodifieddate == self.niahid_entry[niahId]['lastmodifieddate']:
                                            check = False
                                        self.niahid_entry[niahId]['lastmodifieddate'] = lastmodifieddate
                                        self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1

                                        fetchData = self.check_niahid_entry(niahId)
                                        if fetchData:
                                            affected_products_versions_old = fetchData[0][7]
                                            for affected_version_nu in affected_products_versions_old:
                                                if affected_version_nu not in affected_products_versions:
                                                    affected_products_versions.append(affected_version_nu)
                                    else:
                                        revision = '0'
                                        self.niahid_entry[niahId] = {}
                                        self.niahid_entry[niahId]['lastmodifieddate'] = lastmodifieddate
                                        self.niahid_entry[niahId]['revision'] = '0'


                                    self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                    self.cursor = self.connection.cursor()
                                    if check:
                                        
                                        try:
                                            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV2}', '{baseMetricV3}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                            self.cursor.execute(query)
                                            self.connection.commit()
                                        except:
                                            try:
                                                desc = {}
                                                query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV2}', '{baseMetricV3}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                                self.cursor.execute(query)
                                                self.connection.commit()        
                                            except:
                                                pass

                                        self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                        self.cursor = self.connection.cursor()

                                        self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                        self.cursor = self.connection.cursor()
                                        
                                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                                        self.cursor.execute(query)
                                        self.connection.commit()
                                        
                                        if niah_version_id in self.versions_entry:
                                            revision = int(self.versions_entry[niah_version_id]) + 1
                                            self.versions_entry[niah_version_id] = int(self.versions_entry[niah_version_id]) + 1
                                        else:
                                            revision = 0
                                            self.versions_entry[niah_version_id] = revision

                                        self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                        self.cursor = self.connection.cursor()
                                        
                                        query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results), revision)
                                        self.cursor.execute(query)
                                        self.connection.commit()

                                        message = "(NIAH-VULN-ID : %s) %s CVE updated for Ubuntu Platform" % (niahId, data_id)
                                        res = check_alerts()
                                        res.update_alerts('cve_id', data_id, lastmodifieddate, message)
                                        

                if self.daily:
                   break
        
            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniDebianDB()
    res.initialize(date_update)
