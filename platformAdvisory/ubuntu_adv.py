from platform import platform
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
#from lib.alearts_manage import check_alerts
#from lib.dateConvert import dateConvert

class moniUbuntuDB():
    def __init__(self):
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
        query = "select cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, revision from vuln_tab where niahid='%s' ORDER BY revision DESC limit 1" % niahId
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

    def sync_ubuntu_json(self, date_update):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            # 'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }

        i = 0

        while True:
            if os.path.isfile('ubuntu_advisory.json'):
                with open('ubuntu_advisory.json', 'r') as f:
                    final_results = json.load(f)
            else:
                final_results = {}
                final_results['data'] = []

            print("Page - %s" % i)
            params = {
                'offset': '%s' % i,
                'limit': '100',
            }
            i = i + 100
            self.run_cmd()
            response = requests.get('https://ubuntu.com/security/cves.json', params=params, headers=headers, timeout=5)
            jsonData = response.json()

            total_results = jsonData['total_results']
            if i > total_results:
                break
            
            cves = jsonData['cves']
            for cve in cves:
                bugs = cve['bugs']
                score = cve['cvss3']
                description = cve['description']
                id = cve['id']
                if 'summary' in cve:
                    summary = cve['summary']
                else:
                    summary = ''
                if 'title' in cve:
                    title = cve['title']
                else:
                    title = ''
                if 'type' in cve:
                    type = cve['type']
                else:
                    type = ''
                notices_ids = cve['notices_ids']
                notices = cve['notices']
                priority = cve['priority']
                published = cve['published']
                references = cve['references']
                cve_status = cve['status']
                description = cve['description']
                usn_id = ''

                
                if len(notices) > 0:
                    for notice in notices:
                        if 'description' in notice:
                            description = notice['description']

                        results = {}
                        results['description'] = description

                        if 'id' in notice:
                            usn_id = notice['id']
                        else:
                            usn_id = ''
                        results['usn_id'] = usn_id
                        if 'published' in notice:
                            published = notice['published']
                        else:
                            published = ''
                        results['published'] = published
                        if 'references' in notice:
                            references = notice['references']
                        else:
                            references = []
                        results['references'] = references
                        releases_packages = []

                        if 'release_packages' in notice:
                            release_packages = notice['release_packages']
                            for platform in release_packages:
                                for det in release_packages[platform]:
                                    res = {}
                                    res['platform'] = platform
                                    is_source = det['is_source']
                                    if is_source:
                                        res['source'] = "yes"
                                    else:
                                        res['source'] = "no"
                                    name = det['name']
                                    res['package'] = name
                                    version = det['version']
                                    res['version'] = version
                                    if 'source_link' in det:
                                        source_link = det['source_link']
                                        res['source_link'] = source_link
                                    if version:
                                        res['status'] = "fixed"
                                    if res not in releases_packages:
                                        releases_packages.append(res)
                        
                        results['releases_packages'] = releases_packages

                        if 'cves_ids' in notice:
                            cve_ids = notice['cves_ids']
                        
                        for cve_id in cve_ids:
                            results['cve_id'] = cve_id

                            if results not in final_results['data']:
                                final_results['data'].append(results)

                results = {}
                results['description'] = description
                results['usn_id'] = usn_id
                results['published'] = published
                results['references'] = references
                releases_packages = []
                results['cve_id'] = id

                check = False

                if 'packages' in cve:
                    packages = cve['packages']
                    for package in packages:
                        name = package['name'] 
                        source = package['source']

                        if 'statuses' in package:
                            check = True
                            statuses = package['statuses']
                            for status_details in statuses:
                                release = status_details['release_codename']
                                status = status_details['status']
                                res = {}
                                res['package'] = name
                                res['source'] = source
                                res['platform'] = release
                                res['status'] = status
                                if res not in releases_packages:
                                    releases_packages.append(res)

                results['releases_packages'] = releases_packages

                if check:
                    if results not in final_results['data']:
                        final_results['data'].append(results)

            with open('ubuntu_advisory.json', 'w') as f:
                json.dump(final_results, f, indent=4)

    
    def get_usn_details(self, usn_id):
        final_results = {}
        final_results['data'] = []

        if usn_id:
            headers = {
                'accept': 'application/json',
            }

            self.run_cmd()
            print('https://ubuntu.com/security/notices/%s.json' % usn_id)
            response = requests.get('https://ubuntu.com/security/notices/%s.json' % usn_id, headers=headers, timeout=3)
            print(response.text)
            jsonData = response.json()

            cves = jsonData['cves']
            for cve in cves:
                bugs = cve['bugs']
                score = cve['cvss3']
                description = cve['description']
                id = cve['id']
                if 'summary' in cve:
                    summary = cve['summary']
                else:
                    summary = ''
                if 'title' in cve:
                    title = cve['title']
                else:
                    title = ''
                if 'type' in cve:
                    type = cve['type']
                else:
                    type = ''
                
                if 'notices_ids' in cve:
                    notices_ids = cve['notices_ids']
                else:
                    notices_ids = []

                if 'notices' in cve:
                    notices = cve['notices']
                else:
                    notices = []

                priority = cve['priority']
                published = cve['published']
                references = cve['references']
                cve_status = cve['status']
                
                if len(notices) > 0:
                    for notice in notices:
                        if 'description' in notice:
                            description = notice['description']

                        results = {}
                        results['description'] = description
                        if 'id' in notice:
                            usn_id = notice['id']
                        else:
                            usn_id = ''
                        results['usn_id'] = usn_id
                        if 'published' in notice:
                            published = notice['published']
                        else:
                            published = ''
                        results['published'] = published
                        if 'references' in notice:
                            references = notice['references']
                        else:
                            references = []
                        results['references'] = references
                        releases_packages = []

                        if 'release_packages' in notice:
                            release_packages = notice['release_packages']
                            for platform in release_packages:
                                for det in release_packages[platform]:
                                    res = {}
                                    res['platform'] = platform
                                    is_source = det['is_source']
                                    if is_source:
                                        res['source'] = "yes"
                                    else:
                                        res['source'] = "no"
                                    name = det['name']
                                    res['package'] = name
                                    version = det['version']
                                    res['version'] = version
                                    if 'source_link' in det:
                                        source_link = det['source_link']
                                        res['source_link'] = source_link
                                    if version:
                                        res['status'] = "fixed"
                                    if res not in releases_packages:
                                        releases_packages.append(res)
                        
                        results['releases_packages'] = releases_packages

                        if 'cves_ids' in notice:
                            cve_ids = notice['cves_ids']
                        
                        for cve_id in cve_ids:
                            results['cve_id'] = cve_id

                            if results not in final_results['data']:
                                final_results['data'].append(results)

                results = {}
                results['description'] = description
                results['usn_id'] = usn_id
                results['published'] = published
                results['references'] = references
                releases_packages = []
                results['cve_id'] = id

                check = False

                if 'packages' in cve:
                    packages = cve['packages']
                    for package in packages:
                        name = package['name'] 
                        source = package['source']

                        if 'statuses' in package:
                            check = True
                            statuses = package['statuses']
                            for status_details in statuses:
                                release = status_details['release_codename']
                                status = status_details['status']
                                res = {}
                                res['package'] = name
                                res['source'] = source
                                res['platform'] = release
                                res['status'] = status
                                res['version'] = status
                                if res not in releases_packages:
                                    releases_packages.append(res)

                results['releases_packages'] = releases_packages
                
                if check:
                    if results not in final_results['data']:
                        final_results['data'].append(results)

        return final_results
    
    def init_json(self, date_update):
        with open("ubuntu_advisory.json", "r") as f:
            jsonData = json.load(f)

        for jdata in tqdm(jsonData['data']):
            description = jdata['description']
            usn_id = jdata['usn_id']
            published = jdata['published']
            references = jdata['references']
            releases_packages = jdata['releases_packages']
            cve_id = jdata['cve_id']

            res = {}
            res['description'] = description
            res['usn_id'] = usn_id
            res['published'] = published
            res['references'] = references
            res['cve_id'] = cve_id
            res['releases_packages'] = releases_packages
            self.parse_json(res, date_update)

    def run_cmd(self):
        os.system("sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        os.system("sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        os.system("sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    def parse_json(self, cve_data, date_update):
        cve_id = cve_data['cve_id']
        data_type = 'CVE'
        lastmodifieddate = date_update
        published = cve_data['published']
        references = cve_data['references']
        description = cve_data['description']
        description = description.replace("'", "")
        usn_id = cve_data['usn_id']
        releases_packages = cve_data['releases_packages']

        infectedPackageDetails = {}
        infectedPackageDetails['details'] = []

        refe = {}
        refe['data'] = []
        for refer in references:
            refe['data'].append(refer)

        desc = {}
        desc['ubuntu'] = description

        cwe_id = {}
        cwe_id['data'] = []

        basemetricv2_data = {}
        basemetricv3_data = {}

        niahId = "NIAH-CVE-%s" % (cve_id.upper())
        niah_version_id = "NIAH-VERSION-PLATFORM-UBUNTU-%s" % (cve_id.upper())

        results = {}
                
        for pkg in releases_packages:
            platform = pkg['platform']
            source = pkg['source']
            if 'status' in pkg:
                status = pkg['status']
            else:
                status = ''
            
            package = pkg['package']
            if 'version' in pkg:
                version = pkg['version']
            else:
                version = status

            niah_product_id = "NIAH-PLATFORM-UBUNTU-%s" % (package.upper())
                    
            res = {}
            res['platform'] = 'linux'
            res['os'] = 'ubuntu'
                        
            vendor = ''
            advisory = 'ubuntu'
            type = 'platform'

            if niah_product_id not in self.product_entry:
                query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '0')" % (niah_product_id, package, vendor, type, advisory, json.dumps(res))
                print(query)
                self.cursor.execute(query)
                self.connection.commit()
                self.product_entry[niah_product_id] = '0'

                query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
                print(query)
                self.cursor.execute(query)
                self.connection.commit()
                        
            res = {}
            res['product'] = package
            res['versions'] = version
            res['platform'] = platform
            res['advisoryid'] = usn_id

            if re.findall(r'\d', str(version)):
                res['version'] = "[0.0:%s)" % version
                res['patch'] = "upgrade %s to %s" % (platform, version)
            else:
                res['version'] = status
                res['patch'] = status

            if niah_product_id not in results:
                results[niah_product_id] = []

            if res not in results[niah_product_id]:
                results[niah_product_id].append(res)
                    
        check = True
        affected_products_versions = []
        affected_products_versions.append(niah_version_id)

        if niahId in self.niahid_entry:
            revision = int(self.niahid_entry[niahId]['revision']) + 1
            #if lastmodifieddate == self.niahid_entry[niahId]['lastmodifieddate']:
            #    check = False
            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
            self.niahid_entry[niahId]['lastmodifieddate'] = lastmodifieddate

            fetchData = self.check_niahid_entry(niahId)
            if fetchData:
                affected_products_versions_old = fetchData[0][7]
                cwe_id = fetchData[0][0]
                refe = fetchData[0][1]
                for refer in references:
                    if refer not in refe['data']:
                        refe['data'].append(refer)
                desc1 = fetchData[0][2]
                desc = fetchData[0][2]
                try:
                    desc['ubuntu'] = description
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

        if check:
            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=cve_id, cwe_ids=json.dumps(cwe_id), references=json.dumps(refe), description=json.dumps(desc), baseMetricV2=json.dumps(basemetricv2_data), baseMetricV3=json.dumps(basemetricv3_data), publishedDate=published, lastModifiedDate=lastmodifieddate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
            print(query)
            self.cursor.execute(query)
            self.connection.commit()

            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
            print(query)
            self.cursor.execute(query)
            self.connection.commit()

            if niah_version_id in self.versions_entry:
                revision = int(self.versions_entry[niah_version_id]) + 1
                self.versions_entry[niah_version_id] = int(self.versions_entry[niah_version_id]) + 1
            else:
                revision = 0
                self.versions_entry[niah_version_id] = revision

            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results), revision)
            print(query)
            self.cursor.execute(query)
            self.connection.commit()

    def getrss(self, date_update):
        self.run_cmd()
        url = "https://ubuntu.com/security/notices/rss.xml"
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })
        self.run_cmd()
        page = requests.get(url, headers=headers, timeout=3)

        results = xmltodict.parse(page.content)
        for item in tqdm(results['rss']['channel']['item']):
            title = item['title']
            link = item['link']
            pub_date = item['pubDate']
            pub_date = pub_date.replace("+0000", "")
            if re.findall(r'(USN-\d+-\d+)', str(link)):
                usn_id = re.findall(r'(USN-\d+-\d+)', str(link))[0]
            else:
                usn_id = ''
            
            jsonData = self.get_usn_details(usn_id)
            
            for jdata in jsonData['data']:
                description = jdata['description']
                usn_id = jdata['usn_id']
                published = jdata['published']
                references = jdata['references']
                cve_id = jdata['cve_id']
                if 'releases_packages' in jdata:
                    print(jdata)
                    releases_packages = jdata['releases_packages']
                    res = {}
                    res['description'] = description
                    res['usn_id'] = usn_id
                    res['published'] = published
                    res['references'] = references
                    res['cve_id'] = cve_id
                    res['releases_packages'] = releases_packages
                    self.parse_json(res, date_update)

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniUbuntuDB()
    res.init_json(date_update)
    #res.getrss(date_update)
    #res.sync_ubuntu_json(date_update)