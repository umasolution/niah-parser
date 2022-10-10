from ensurepip import version
from struct import pack
import requests
import json
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

class moniRedhatDB():
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
    
    def parse_json(self, cve_data, date_update):
        cve_id = cve_data['cve_id']
        data_type = 'CVE'
        lastmodifieddate = date_update
        published = cve_data['published']
        references = cve_data['references']
        description = cve_data['description']
        description = description.replace("'", "")
        advisoryid = cve_data['advisoryid']
        cwe = cve_data['cwe_id']
        releases_packages = cve_data['releases_packages']

        infectedPackageDetails = {}
        infectedPackageDetails['details'] = []

        refe = {}
        refe['data'] = []
        for refer in references:
            refe['data'].append(refer)

        desc = {}
        desc['redhat'] = description

        cwe_id = {}
        cwe_id['data'] = []
        if cwe not in cwe_id['data']:
            cwe_id['data'].append(cwe)

        basemetricv2_data = {}
        basemetricv3_data = {}

        niahId = "NIAH-CVE-%s" % (cve_id.upper())
        niah_version_id = "NIAH-VERSION-PLATFORM-REDHAT-%s" % (cve_id.upper())

        results = {}
                
        for pkg in releases_packages:
            platform = pkg['platform']            
            package = pkg['package']
            status = pkg['status']
            version = pkg['version']

            niah_product_id = "NIAH-PLATFORM-REDHAT-%s" % (package.upper())
                    
            res = {}
            res['platform'] = 'linux'
            res['os'] = 'redhat'
                        
            vendor = ''
            advisory = 'redhat'
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
            res['advisoryid'] = advisoryid

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


    def get_resource(self, url):
        response = requests.get(url)
        jsonData = response.json()

        published = jsonData['public_date']
        reference = ''
        cwe_id = ''
        description = ''

        if 'bugzilla' in jsonData:
            if 'description' in jsonData['bugzilla']:
                description = jsonData['bugzilla']['description']
            if 'url' in jsonData['bugzilla']:
                reference = jsonData['bugzilla']['url']
        if 'cwe' in jsonData:
            cwe_id = jsonData['cwe']
        if not description:
            if 'details' in jsonData:
                details = jsonData['details']
        
        results = {}
        results['description'] = description
        results['published'] = published
        results['references'] = reference
        results['cwe_id'] = cwe_id
        releases_packages = []
        adv_ids = []

        if 'affected_release' in jsonData:
            affected_release = jsonData['affected_release']
            for affpkg in affected_release:
                platform = affpkg['product_name']
                advisoryid = affpkg['advisory']
                if advisoryid not in adv_ids:
                    adv_ids.append(advisoryid)
                package = affpkg['package']
                if re.findall(r'(.*?)-(.*)', str(package)):
                    packagename = re.findall(r'(.*?)-(.*)', str(package))[0][0]
                    version = re.findall(r'(.*?)-(.*)', str(package))[0][1]
                else:
                    packagename = package
                    version = '*'

                res = {}
                res['platform'] = platform
                res['package'] = package
                res['version'] = version
                res['status'] = "fixed"
                if res not in releases_packages:
                    releases_packages.append(res)

        if 'package_state' in jsonData:
            package_state = jsonData['package_state']
            for pkgs in package_state:
                platform = pkgs['product_name']
                status = pkgs['fix_state']
                package = pkgs['package_name']
                res = {}
                res['platform'] = platform
                res['package'] = package
                res['version'] = status
                res['status'] = status
                if res not in releases_packages:
                    releases_packages.append(res)

        results['advisoryid'] = ','.join(adv_ids)
        results['releases_packages'] = releases_packages
        cve_id = jsonData['name']
        results['cve_id'] = cve_id
        return results
    
    def get_rss(self, date_update):
        i = 1

        while True:
            response = requests.get('https://access.redhat.com/hydra/rest/securitydata/cve.json?page=%s' % i)
            jsonData = response.json()
            if len(jsonData) == 0:
                break

            print("[ OK ] total data - %s" % len(jsonData))
            for data in jsonData:
                resource_url = data['resource_url']
                print("[ OK ] Resource URL - %s" % resource_url)
                results = self.get_resource(resource_url)
                
                self.parse_json(results, date_update)
            
            i = i + 1


if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = moniRedhatDB()
    res.get_rss(date_update)