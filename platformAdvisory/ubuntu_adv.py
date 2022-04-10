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

class moniUbuntuDB():
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


    def check_product_entry(self, niah_product_id):
        query = "select * from product_reference_tab where niah_product_id='%s'" % niah_product_id
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            return False
        else:
            return True

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

    def check_version_entry(self, niah_version_id):
        self.connection = psycopg2.connect(user='versa',password='versa123',host='127.0.0.1',port="5432",database='niahdb')
        self.cursor = self.connection.cursor()
        query = "select * from affected_versions_tab where niah_version_id='%s'" % niah_version_id
        #self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()
        if len(fetchData) > 0:
            return False
        else:
            return True


    def getCVEDetails(self, cve_id):
        results = {}
        results["details"] = []
        results["pub_date"] = ''
        pub_date = ''
        url = 'https://ubuntu.com/security/%s' % cve_id
        page = requests.get(url)
        soup = BeautifulSoup(page.text, "html.parser")

        for tbl in soup.findAll('table', {'class': 'cve-table'}):
            for tr in tbl.findAll('tr'):
                tds = tr.findAll('td')
                if len(tds) == 3:
                    i = 0
                    for td in tds:
                        platform = ''
                        versions = ''
                    
                        if i == 0:
                            res = {}
                            package = td.findAll('a')[0].text
                            res["product"] = str(package)
                        if i == 1:
                            platform = td.text.strip()
                            platform = platform.replace('"', '')
                            if re.findall(r'(Ubuntu\s+\d+.\d+.*)\s+\(', str(platform)):
                                platform = re.findall(r'(Ubuntu\s+\d+.\d+.*)\s+\(', str(platform))[0]
                            else:
                                platform = str(platform.replace('"', ""))
                            res["platform"] = str(platform)
                        if i == 2:
                            versionTxt = td.text
                            if re.findall(r'Released\s+\((.*)\)', str(versionTxt)):
                                versions = re.findall(r'Released\s+\((.*)\)', str(versionTxt))[0]
                            elif re.findall(r'Does not exist', str(versionTxt)):
                                pass
                            elif re.findall(r'Not vulnerable', str(versionTxt)):
                                pass
                            elif re.findall(r'Ignored', str(versionTxt)):
                                pass
                            elif re.findall(r'Pending\s+\((.*)\)', str(versionTxt)):
                                versions = re.findall(r'Pending\s+\((.*)\)', str(versionTxt))[0]
                            elif re.findall(r'Needs triage', str(versionTxt)):
                                versions = "*"
                            elif re.findall(r'Needed', str(versionTxt)):
                                versions = "*"
                            res["versions"] = str(versions)
                            results["details"].append(res)
                        i = i + 1
                if len(tds) == 2:
                    i = 0
                    for td in tds:
                        platform = ''
                        versions = ''
                        if i == 0:
                            res = {}
                            res["product"] = str(package)
                            platform = td.text.strip()
                            platform = platform.replace('"', '')
                            if re.findall(r'(Ubuntu\s+\d+.\d+.*)\s+\(', str(platform)):
                                platform = re.findall(r'(Ubuntu\s+\d+.\d+.*)\s+\(', str(platform))[0]
                            else:
                                platform = str(platform.replace('"', ""))
                            res["platform"] = str(platform)
                        if i == 1:
                            versionTxt = td.text
                            if re.findall(r'Released\s+\((.*)\)', str(versionTxt)):
                                versions = re.findall(r'Released\s+\((.*)\)', str(versionTxt))[0]
                            elif re.findall(r'Does not exist', str(versionTxt)):
                                pass
                            elif re.findall(r'Not vulnerable', str(versionTxt)):
                                pass
                            elif re.findall(r'Ignored', str(versionTxt)):
                                pass
                            elif re.findall(r'Pending\s+\((.*)\)', str(versionTxt)):
                                versions = re.findall(r'Pending\s+\((.*)\)', str(versionTxt))[0]
                            elif re.findall(r'Needs triage', str(versionTxt)):
                                versions = "*"
                            elif re.findall(r'Needed', str(versionTxt)):
                                versions = "*"
                            res["versions"] = str(versions)
                            results["details"].append(res)
                        i = i + 1

        for div in soup.findAll('div', {'class': 'row'}):
            if "Published:" in str(div):
                pub_date = div.findAll('strong')[0].text
                res1 = dateConvert() 
                pub_date = res1.dateCon(pub_date)
                break
        
        results["pub_date"] = pub_date
        return results
        
    def getrss(self, date_update):
        url = "https://ubuntu.com/security/notices/rss.xml"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })
        page = requests.get(url, headers=headers)

        results = xmltodict.parse(page.content)
        for item in tqdm(results['rss']['channel']['item']):
            pub_date = ''
            title = item['title']
            link = item['link']
            pub_date = item['pubDate']
            pub_date = pub_date.replace("+0000", "")

            if re.findall(r'notices\/(USN-.*)$', str(link)):
                usn_id = re.findall(r'notices\/(USN-.*)$', str(link))[0]
                reference = "https://ubuntu.com/security/notices/%s" % usn_id
            else:
                usn_id = ''
                reference = ''

            description = item['description'].replace("\n", " ")
            summary = description.replace("'", "")

            cwe_id = {}
            cwe_id['data'] = []

            refe = {}
            refe['data'] = []
            refe['data'].append(reference)

            desc = {}
            desc['ubuntu'] = summary

            basemetricv2_data = {}
            basemetricv3_data = {}


            if usn_id:
                aUrl = link
                name = description
                name = name.replace("'", "")
                
                headers = requests.utils.default_headers()
                headers.update({
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                })

                page = requests.get(link, headers=headers)
                soup = BeautifulSoup(page.content, "html.parser")

                if not pub_date:
                    pub_date = soup.findAll('p', {'class':'p-muted-heading'})
                
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:	
                    pub_date = ''

                cves = re.findall(r'CVE-\d+-\d+', str(soup), re.IGNORECASE)
                cves = ','.join(list(set(cves)))

                sections = soup.findAll('section', {'class':'p-strip--suru-topped'})

                divs = sections[0].findAll('div', {'class':'row'})
                for div1 in divs:
                    for div in div1.findAll('div', {'class':'row'}):
                        if re.findall(r'Update instructions', str(div)):
                            h5Array = div.findAll('h5')
                            ulArray = div.findAll('ul')

                            ulA = []
                            h5A = []
                            for h5 in h5Array:
                                h5 = h5.text
                                h5 = h5.strip()
                                h5 = re.sub(r'\n\s+', '', str(h5))
                                h5A.append(h5)

                            for ul in ulArray:
                                ul = ul.text
                                ul = re.sub(r'\n\s+', ' ', str(ul))
                                ulA.append(ul.strip())

                            dictA = dict(zip(ulA, h5A))

                platformArray = []
                infectedPackageDetails = {}
                infectedPackageDetails['details'] = []
                for k, v in dictA.items():
                    product = k.split(" - ")[0]
                    product = product.lower()
                    version = k.split(" - ")[1]
                    platform_os = v

                    res = {}
                    res["product"] = str(product)
                    res["versions"] = str(version)
                    res["platform"] = platform_os
                    platformArray.append(platform_os)
                    infectedPackageDetails['details'].append(res)

                    niah_product_id = "NIAH-PLATFORM-UBUNTU-%s" % (product.upper())

                    res = {}
                    res['platform'] = 'linux'
                    res['os'] = 'ubuntu'
                    
                    vendor = ''
                    advisory = 'ubuntu'
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



                platform = ','.join(platformArray)
                infectedPackageDetails1 = str(infectedPackageDetails)

                for cve in cves.split(','):
                    if re.findall(r'CVE-\d+-\d+', str(cve), re.IGNORECASE):
                        pkgVersDetails = self.getCVEDetails(cve)		
                        if len(pkgVersDetails) > 0:
                            infectedPackageDetails = {}
                            infectedPackageDetails["details"] = pkgVersDetails["details"]
                            if pkgVersDetails["pub_date"]:
                                if not pub_date:
                                    pub_date = pkgVersDetails["pub_date"]
                            infectedPackageDetails = infectedPackageDetails
                    
                        niahId = "NIAH-CVE-%s" % (cve)
                        publisheddate = pub_date
                        lastmodifieddate = pub_date
                        data_type = 'CVE'
                        data_id = cve
                        niah_version_id = "NIAH-VERSION-PLATFORM-UBUNTU-%s" % (cve.upper())
                        
                        results = {}

                        for det in infectedPackageDetails['details']:
                            product = det['product']
                            platform = det['platform']
                            versions = det['versions']

                            niah_product_id = "NIAH-PLATFORM-UBUNTU-%s" % (product.upper())
                            

                            res = {}
                            res['platform'] = 'linux'
                            res['os'] = 'ubuntu'
                            
                            vendor = ''
                            advisory = 'ubuntu'
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
                            res['advisoryid'] = usn_id
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
                                cwe_id = fetchData[0][0]
                                refe = fetchData[0][1]
                                refe['data'].append(reference)
                                desc1 = fetchData[0][2]
                                desc = fetchData[0][2]
                                desc['ubuntu'] = summary
                                try:
                                    desc['ubuntu'] = summary
                                except:
                                    desc = desc1
                                basemetricv3_data = fetchData[0][3]
                                basemetricv2_data = fetchData[0][4]

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
                                query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                self.cursor.execute(query)
                                self.connection.commit()
                            except:
                                try:
                                    desc = desc1
                                    query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                    self.cursor.execute(query)
                                    self.connection.commit()        
                                except:
                                    pass

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            self.cursor.execute(query)
                            self.connection.commit()
                            
                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = int(self.versions_entry[niah_version_id]) + 1
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision
                

                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results), revision)
                            self.cursor.execute(query)
                            self.connection.commit()

                            message = "(NIAH-VULN-ID : %s) %s CVE updated for Debian Platform" % (niahId, data_id)
                            res = check_alerts()
                            res.update_alerts('cve_id', data_id, lastmodifieddate, message)


    def initialize(self, date_update):
        print("[ OK ] Ubuntu RSS Feed sync")
        self.getrss(date_update)
        print("[ OK ] Ubuntu advisory first page sync")
        date_update = date_update
        url = "https://usn.ubuntu.com/"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(url, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        #i1 = 166
        i1 = 1
        while True:
            print("#### - %s" % i1)
            url = "https://ubuntu.com/security/notices?page=%s" % i1
            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })


            page = requests.get(url, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")

            if not self.daily:
                if re.findall(r'404: Page not found', str(soup)):
                    break

            articles = soup.findAll('article',{'class':'notice'})

            for article in tqdm(articles):
                aTag = article.findAll('a')
            
                aUrl = aTag[0].get('href')
                aUrl = "https://ubuntu.com%s" % aUrl
                name = article.findAll('h3')[0].text
                name = name[:-2]
                name = name.replace("'", "")

                urlSub = aUrl
                usn = urlSub.split("/")[-1]
                usn_id = usn
               
                reference = "https://ubuntu.com/security/notices/%s" % usn_id

                cwe_id = {}
                cwe_id['data'] = []

                refe = {}
                refe['data'] = []
                refe['data'].append(reference)

                desc = {}
                desc['ubuntu'] = name

                basemetricv2_data = {}
                basemetricv3_data = {}

                headers = requests.utils.default_headers()
                headers.update({
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                })

                page = requests.get(urlSub, headers=headers, stream=True)
                soup = BeautifulSoup(page.content, "html.parser")

                pub_date = soup.findAll('p', {'class':'p-muted-heading'})
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:	
                    pub_date = ''

                cves = re.findall(r'CVE-\d+-\d+', str(soup), re.IGNORECASE)
                cves = ','.join(list(set(cves)))

                if soup.findAll('section', {'class':'p-strip--suru-topped'}):
                    sections = soup.findAll('section', {'class':'p-strip--suru-topped'})
                    divs = sections[0].findAll('div', {'class':'row'})
                else:
                    divs = []

                summary = ''	
                if len(divs) > 0:
                    for div1 in divs:
                        for div in div1.findAll('div', {'class':'row'}):
                            if re.findall(r'<h2>Details', str(div)):
                                desc = div.text
                                desc = desc.strip()
                                desc = desc.replace("\n", " ")
                                #summary1 = re.sub(r'^Details\s', '', str(desc.encode("utf-8")))
                                #summary1 = summary1.replace("'", "")
                                summary = desc.replace("'", "")

                            if re.findall(r'Update instructions', str(div)):
                                h5Array = div.findAll('h5')
                                ulArray = div.findAll('ul')

                                ulA = []
                                h5A = []
                                for h5 in h5Array:
                                    h5 = h5.text
                                    h5 = h5.strip()
                                    h5 = re.sub(r'\n\s+', '', str(h5))
                                    h5A.append(h5)

                                for ul in ulArray:
                                    ul = ul.text
                                    ul = re.sub(r'\n\s+', ' ', str(ul))
                                    ulA.append(ul.strip())

                                dictA = dict(zip(ulA, h5A))

                    platformArray = []
                    infectedPackageDetails = {}
                    infectedPackageDetails["details"] = []
                    for k, v in dictA.items():
                        product = k.split(" - ")[0]
                        try:
                            version = k.split(" - ")[1]
                        except:
                            version = ''
                        
                        platform_os = v

                        res = {}
                        res["product"] = str(product)
                        res["versions"] = str(version)
                        res["platform"] = platform_os
                        platformArray.append(platform_os)
                        infectedPackageDetails["details"].append(res)

                    platform = ','.join(platformArray)
                    infectedPackageDetails1 = str(infectedPackageDetails)

                    for cve in cves.split(','):
                        if re.findall(r'CVE-\d+-\d+', str(cve), re.IGNORECASE):
                            pkgVersDetails = self.getCVEDetails(cve)		
                            if len(pkgVersDetails) > 0:
                                infectedPackageDetails = {}
                                infectedPackageDetails["details"] = pkgVersDetails["details"]
                                if pkgVersDetails["pub_date"]:
                                    pub_date = pkgVersDetails["pub_date"]
                                infectedPackageDetails = infectedPackageDetails
                        
                            niahId = "NIAH-CVE-%s" % (cve)
                            publisheddate = pub_date
                            lastmodifieddate = pub_date
                            data_type = 'CVE'
                            data_id = cve
                            niah_version_id = "NIAH-VERSION-PLATFORM-UBUNTU-%s" % (cve.upper())
                            
                            results = {}

                            for det in infectedPackageDetails['details']:
                                product = det['product']
                                platform = det['platform']
                                versions = det['versions']

                                niah_product_id = "NIAH-PLATFORM-UBUNTU-%s" % (product.upper())
                                

                                res = {}
                                res['platform'] = 'linux'
                                res['os'] = 'ubuntu'
                                
                                vendor = ''
                                advisory = 'ubuntu'
                                type = 'platform'

                                self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                self.cursor = self.connection.cursor()
                                if niah_product_id not in self.product_entry:
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
                                res['advisoryid'] = usn_id
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
                                    cwe_id = fetchData[0][0]
                                    refe = fetchData[0][1]
                                    refe['data'].append(reference)
                                    desc1 = fetchData[0][2]
                                    desc = fetchData[0][2]
                                    try:
                                        desc['ubuntu'] = name
                                    except:
                                        desc = desc1
                                    basemetricv3_data = fetchData[0][3]
                                    basemetricv2_data = fetchData[0][4]

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
                                    query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                                    self.cursor.execute(query)
                                    self.connection.commit()
                                except:
                                    try:
                                        desc = desc1
                                        query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=publisheddate, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
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

                                self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
                                self.cursor = self.connection.cursor()
                                query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results), revision)
                                self.cursor.execute(query)
                                self.connection.commit()

                                message = "(NIAH-VULN-ID : %s) %s CVE updated for Debian Platform" % (niahId, data_id)
                                res = check_alerts()
                                res.update_alerts('cve_id', data_id, lastmodifieddate, message)


            i1 = i1 + 1
            if self.daily:
                if i1 > 1:
                    break
            

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniUbuntuDB()
    res.initialize(date_update)
