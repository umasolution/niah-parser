from bs4 import BeautifulSoup
import time
import requests
import datetime
import re
import sys
import configparser
import sqlite3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import json
from lib.dateConvert import dateConvert
from lib.alearts_manage import check_alerts
import psycopg2
import json
from tqdm import tqdm
import os
import glob

__all__ = ["getstatusoutput","getoutput","getstatus"]

def getstatus(file):
    """Return output of "ls -ld <file>" in a string."""
    import warnings
    warnings.warn("commands.getstatus() is deprecated", DeprecationWarning, 2)
    return getoutput('ls -ld' + mkarg(file))

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

class GHSAdvisory():
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

        query = "select niahid, revision, lastmodifieddate from vuln_tab ORDER BY revision DESC;"
        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()
            
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
        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()
            
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        self.product_entry = {}

        for data in fetchData:
            niah_product_id = data[0]
            revision = data[1]

            if niah_product_id not in self.product_entry:
                self.product_entry[niah_product_id] = revision


        query = "select niah_version_id, revision from affected_versions_tab ORDER BY revision DESC;"
        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()
            
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        self.versions_entry = {}

        for data in fetchData:
            niah_version_id = data[0]
            revision = data[1]

            if niah_version_id not in self.versions_entry:
                self.versions_entry[niah_version_id] = revision


    def check_productid_entry(self, niah_product_id):
        self.connection = psycopg2.connect(user='versa',password='versa123',host='127.0.0.1',port="5432",database='niahdb')
        self.cursor = self.connection.cursor()
        query = "select product, vendor, advisory, type, data, revision from product_reference_tab where niah_product_id='%s'" % niah_product_id
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            return fetchData
        else:
            return False
    
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

    def uniqCVEs(self, cves):
        res = []
        for cve in cves:
            if cve not in res:
                res.append(cve)
        return res


    def getMax(self, values):
        val1 = 0
        for val in values:
            if val > val1:
                val1 = val

        return val1 

    def get_next_num(self):
        query = "select max(id) from vuln_tab"
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()
        return fetchData[0][0] + 1

    def initialize(self, date_update):
        print("[ OK ] GHSAdvisory Sync Started")
        #cmd = "sudo sysctl -p"
        #status, output = getstatusoutput(cmd)

        cmd = "rm -rf advisory-database"
        print(cmd)
        status, output = getstatusoutput(cmd)

        cmd = "git clone --depth 1 https://github.com/github/advisory-database.git"
        print(cmd)
        status, output = getstatusoutput(cmd)
        print(output)

        for filename in glob.iglob('advisory-database/advisories/github-reviewed/**/*.json', recursive = True):
            print(filename)
            with open(filename, "r") as f:
                jsondata = json.load(f)

            results = self.parser_json(jsondata)
            self.update_db(results)


    def parser_json(self, jsondata):
        id = jsondata['id']
        modified = jsondata['modified']
        published = jsondata['published']
        aliases = jsondata['aliases']
        if 'summary' in jsondata:
            summary = jsondata['summary']
        else:
            summary = jsondata['details']
        
        severity = ''
        if 'severity' in jsondata:
            severity = jsondata['severity']

        cwe_ids = []
        if 'database_specific' in jsondata:
            if 'cwe_ids' in jsondata['database_specific']:
                cwe_ids = jsondata['database_specific']['cwe_ids']

        references = []
        if 'references' in jsondata:
            refers = jsondata['references']
            for ref in refers:
                if ref['url'] not in references:
                    references.append(ref['url'])

        affected_packages = jsondata['affected']

        results = []
        for affected_package in affected_packages:
            packagename = ''
            groupid = ''
            artifactid = ''
            application = ''
            product = ''
            vendor = ''
            versions = []

            check = False
            if 'package' in affected_package:
                packagename = affected_package['package']['name'].lower()
                ecosystem = affected_package['package']['ecosystem'].lower()
                
                if ecosystem == "maven":
                    groupid = packagename.split(":")[0]
                    artifactid = packagename.split(":")[1]
                    application = "java"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "composer" or ecosystem == "packagist":
                    application = "php"
                    vendor = ''
                    if "/" in packagename:
                        product = packagename.split("/")[1]
                        vendor = packagename.split("/")[0]
                    else:
                        product = packagename
                        vendor = ''
                    check = True
                elif ecosystem == "npm":
                    application = "javascript"
                    vendor = ''
                    if "/" in packagename:
                        product = packagename.split("/")[1]
                        vendor = packagename.split("/")[0]
                    else:
                        product = packagename
                        vendor = ''
                    check = True
                elif ecosystem == "pip" or ecosystem == "pypi":
                    application = "python"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "nuget":
                    application = "dotnet"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "rubygems":
                    application = "ruby"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "go":
                    application = "golang"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "rust" or ecosystem == "crates.io":
                    application = "rust"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "hex":
                    application = "erlang"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "pub":
                    application = "dart"
                    product = packagename
                    vendor = ''
                    check = True
                elif ecosystem == "github actions":
                    application = "github-actions"
                    if "/" in packagename:
                        product = packagename.split("/")[1]
                        vendor = packagename.split("/")[0]
                    else:
                        product = packagename
                        vendor = ''
                    check = True

            if check:
                if 'ranges' in affected_package:
                    versions = []
                    patches = []
                    ranges = affected_package['ranges']
                    for rang in ranges:
                        fixed = ''
                        last_affected = ''
                        if 'events' in rang:
                            for event in rang['events']:
                                if 'introduced' in event:
                                    introduced = event['introduced']
                                if 'fixed' in event:
                                    fixed = event['fixed']
                                elif 'last_affected' in event:
                                    last_affected = event['last_affected']
                            
                            if fixed:
                                vers = "[%s:%s)" % (introduced, fixed)
                                patch = "update %s version" % last_affected
                            elif last_affected:
                                vers = "[%s:%s]" % (introduced, last_affected)
                                patch = "update latest release version after %s" % fixed
                            else:
                                vers = '0'
                                patch = "no patch"
                            
                            if patch not in patches:
                                patches.append(patch)

                            if vers not in versions:
                                versions.append(vers)
                else:
                    versions = []
                    patches = []
                    

            """
            print(id)
            print(cwe_ids)
            print(application)
            print(product)
            print(vendor)
            print(ecosystem)
            print(aliases)
            print(references)
            print("application - %s" % application)
            print("packagename - %s" % packagename)
            print("versions - %s" % versions)
            print("===========")
            """

            if len(aliases) > 0:
                for cve_id in aliases:
                    res = {}
                    res['ghsaid'] = id
                    res['cve_id'] = cve_id
                    res['cwe_ids'] = cwe_ids
                    res['application'] = application
                    res['product'] = product
                    res['vendor'] = vendor
                    res['ecosystem'] = ecosystem
                    res['references'] = references
                    res['packagename'] = packagename
                    res['versions'] = versions
                    res['severity'] = severity
                    res['published'] = published
                    res['modified'] = modified
                    res['summary'] = summary
                    if groupid:
                        res['groupid'] = groupid
                    if artifactid:
                        res['artifactid'] = artifactid
                    res['patch'] = ','.join(patches)

                    results.append(res)
            else:
                res = {}
                res['ghsaid'] = id
                res['cwe_ids'] = cwe_ids
                res['application'] = application
                res['product'] = product
                res['vendor'] = vendor
                res['ecosystem'] = ecosystem
                res['references'] = references
                res['packagename'] = packagename
                res['versions'] = versions
                res['severity'] = severity
                res['published'] = published
                res['modified'] = modified
                res['summary'] = summary
                if groupid:
                    res['groupid'] = groupid
                if artifactid:
                    res['artifactid'] = artifactid
                res['patch'] = ','.join(patches)

                results.append(res)

        return results


    def update_db(self, jsondatas):
        for jsondata in jsondatas:
            if 'cve_id' in jsondata:
                cve_id = jsondata['cve_id']
                data_id = cve_id
                data_type = "CVE"
            else:
                cve_id = jsondata['ghsaid']
                data_id = cve_id
                data_type = "NOCVE"
                
            packagename = jsondata['packagename']
            cwe_ids = jsondata['cwe_ids']
            versions = jsondata['versions']
            application = jsondata['application']
            patch = jsondata['patch']
            product = jsondata['product']
            vendor = jsondata['vendor']
            if 'groupid' in jsondata:
                groupid = jsondata['groupid']
            else:
                groupid = ''
            if 'artifactid' in jsondata:
                artifactid = jsondata['artifactid']
            else:
                artifactid = ''
            ecosystem = jsondata['ecosystem']
            ghsaid = jsondata['ghsaid']
            referes = jsondata['references']
            severity = jsondata['severity']
            publisheddate = jsondata['published']
            lastModifiedDate = jsondata['modified']
            date_update = lastModifiedDate
            vuln_name = jsondata['summary']
            vuln_name = vuln_name.replace("'", "")


            cwe_ids = {}
            cwe_ids['data'] = []
            for cwe_text in cwe_ids:
                cwe_ids['data'].append(cwe_text)

            references = {}
            references['data'] = []
            for refe in referes:
                refe = refe.replace("'","")
                references['data'].append(refe)

            description = {}
            description['ghsa'] = vuln_name

            baseMetricV3 = {}
            baseMetricV3['baseSeverity'] = severity
            baseMetricV2 = {}
            baseMetricV2['severity'] = severity

            affected_version = {}
            affected_version['product'] = product
            affected_version['vendor'] = vendor
            affected_version['patch'] = patch
            affected_version['version'] = versions

            res = {}
            res['language'] = application
            res['part'] = 'a'
            res['ecosystem'] = ecosystem
            res['packagename'] = packagename
            if groupid:
                res['groupid'] = groupid
            if artifactid:
                res['artifactid'] = artifactid
                            
            type ="NVD"
            advisory = 'GHSA'

            if product and vendor:
                niah_product_id = "NIAH-NVD-GHSA-%s-%s" % (vendor.upper(), product.upper())
            else:
                niah_product_id = "NIAH-NVD-GHSA-%s" % (product.upper())

            fetchData = self.check_productid_entry(niah_product_id)
                                
            pcheck = True
            if fetchData:
                fetchData.sort(key=lambda x: x[5], reverse=True)
                res = fetchData[0][4]
                if 'language' in res:
                    if res['language'] == application:
                        pcheck = False
                res['language'] = application
                res['ecosystem'] = ecosystem
                res['part'] = 'a'
                revision = fetchData[0][5] + 1
            else:
                revision = '0'
            
            if pcheck: 
                query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res), revision)
                self.cursor.execute(query)
                self.connection.commit()
                self.product_entry[niah_product_id] = revision

                query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
                self.cursor.execute(query)
                self.connection.commit()

            
            affected_products_versions = []
            results = {}

            niahId = "NIAH-%s-%s" % (data_type, data_id)
            niah_version_id = "NIAH-VERSION-NVD-GHSA-%s" % data_id

            fetchData = self.check_niahid_entry(niahId)
            if fetchData:
                fetchData.sort(key=lambda x: x[8], reverse=True)
                cwe_ids = fetchData[0][0]
                if len(cwe_ids) > 0:
                    for cwe_text in cwe_ids:
                        cwe_ids['data'].append(cwe_text)

                references = fetchData[0][1]
                if len(referes) > 0:
                    for refe in referes:
                        refe = refe.replace("'","")
                        references['data'].append(refe)

                try:
                    description = fetchData[0][2]
                    description['ghsa'] = vuln_name
                except:
                    description = {}
                    description['nvd'] = vuln_name

                baseMetricV3 = fetchData[0][3]
                if baseMetricV3:
                    baseMetricV3['baseSeverity'] = severity

                baseMetricV2 = fetchData[0][4]
                if baseMetricV2:
                    baseMetricV2['severity'] = severity

                if not publisheddate:
                    publisheddate = fetchData[0][5]

                if not lastModifiedDate:
                    lastModifiedDate = fetchData[0][6]

                affected_products_versions = fetchData[0][7]
                if affected_products_versions:
                    if niah_version_id not in affected_products_versions:
                        affected_products_versions.append(niah_version_id)
                revision = fetchData[0][8] + 1
                
                affected_version = {}
                affected_version['product'] = product
                affected_version['vendor'] = vendor
                affected_version['patch'] = patch
                affected_version['version'] = versions

                if niah_version_id not in results:
                    results[niah_version_id] = {}

                if niah_product_id not in results[niah_version_id]:
                    results[niah_version_id][niah_product_id] = []

                if affected_version not in results[niah_version_id][niah_product_id]:
                    results[niah_version_id][niah_product_id].append(affected_version)
            else:
                if niah_version_id not in results:
                    results[niah_version_id] = {}

                if niah_product_id not in results[niah_version_id]:
                    results[niah_version_id][niah_product_id] = []

                if affected_version not in results[niah_version_id][niah_product_id]:
                    results[niah_version_id][niah_product_id].append(affected_version)

                if niah_version_id not in affected_products_versions:
                    affected_products_versions.append(niah_version_id)

            check = True

            if niahId in self.niahid_entry:
                revision = int(self.niahid_entry[niahId]['revision']) + 1
                if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                    check = False
                self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
            else:
                revision = '0'
                self.niahid_entry[niahId] = {}
                self.niahid_entry[niahId]['revision'] = '0'
                self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

            if check:
                query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publisheddate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                print(query)
                self.cursor.execute(query)
                self.connection.commit()

                query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                print(query)
                self.cursor.execute(query)
                self.connection.commit()

                if niah_version_id in self.versions_entry:
                    revision = int(self.versions_entry[niah_version_id]) + 1
                    self.versions_entry[niah_version_id] = revision
                else:
                    revision = 0
                    self.versions_entry[niah_version_id] = revision

                query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                print(query)
                self.cursor.execute(query)
                self.connection.commit() 

            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = GHSAdvisory()
    res.initialize(date_update)
    #url = "https://github.com/advisories/GHSA-5vjc-qx43-r747"
    #res.getIssueDetails(url)
