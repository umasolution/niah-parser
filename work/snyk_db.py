from email.mime import application
from unittest import result
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
from lib.dateConvert import dateConvert

class snyk_db():
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
        query = "select cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, revision from vuln_tab where niahid='%s'" % niahId
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            return fetchData
        else:
            return False

    def snyc_maven(self, date_update):
        with open("maven_vulns.json", "r") as f:
            json_data = json.load(f)

        application = "java"

        for data in json_data:
            packagename = data['packagename']
            home_url = data['home_url']
            groupid = data['groupid']
            artifactid = data['artifactid']
            
            if 'github' in data:
                github = data['github']
            else:
                github = ''

            product = artifactid
            vendor = groupid

            type ="NVD"
            advisory = 'ADV'

            niah_product_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())
                
            if niah_product_id in self.product_entry:
                revision = int(self.product_entry[niah_product_id]) + 1
            else:
                revision = '0'
                    
            fetchData = self.check_productid_entry(niah_product_id)
                                        
            if fetchData:
                fetchData.sort(key=lambda x: x[5], reverse=True)
                res = fetchData[0][4]
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'maven'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
                res['groupid'] = groupid
                res['artifactid'] = artifactid
            else:
                res = {}
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'maven'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
                res['groupid'] = groupid
                res['artifactid'] = artifactid
                revision = '0'

            query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res), revision)
            self.cursor.execute(query)
            self.connection.commit()
            self.product_entry[niah_product_id] = revision
                
            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
            self.cursor.execute(query)
            self.connection.commit()

            inc_no = 1
            for vuln in tqdm(data['vulns']):
                vuln_name = vuln['vuln_name']
                vuln_name = vuln_name.replace("'", "")
                versions = vuln['versions']
                pub_date = vuln['pub_date']
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:
                    pass
                cves = vuln['cves']
                cweid = vuln['cweid']
                severity = vuln['severity']
                if severity.lower() == "moderate":
                    severity = "medium"
                severity = severity.upper()
                score = vuln['score']
                reference = vuln['reference']

                publishedDate = pub_date
                publisheddate = pub_date
                lastModifiedDate = pub_date
                

                affected_version = {}
                affected_version['product'] = product
                affected_version['vendor'] = vendor
                affected_version['patch'] = "upgrade latest version"
                affected_version['version'] = versions

                if not cves:
                    cves = []

                if len(cves) > 0:
                    for cve_id in cves:
                        results = {}
                        affected_products_versions = []
                        data_type = "CVE"
                        data_id = cve_id

                        niahId = "NIAH-%s-%s" % (data_type, data_id)
                        niah_version_id = "NIAH-VERSION-NVD-NIAH-%s" % data_id

                        fetchData = self.check_niahid_entry(niahId)
                        if fetchData:
                            fetchData.sort(key=lambda x: x[8], reverse=True)
                            cwe_ids = fetchData[0][0]
                            cwe_ids['data'].append(cweid)
                            references = fetchData[0][1]
                            references['data'].append(reference)
                            try:
                                description = fetchData[0][2]
                                description['niah'] = vuln_name
                            except:
                                description = {}
                                description['niah'] = vuln_name
                            baseMetricV3 = fetchData[0][3]
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV2 = fetchData[0][4]
                            baseMetricV2['severity'] = severity
                            publisheddate = fetchData[0][5]
                            lastModifiedDate = fetchData[0][6]
                            affected_products_versions = fetchData[0][7]
                            affected_products_versions.append(niah_version_id)
                            revision = fetchData[0][8] + 1

                            if niah_version_id not in results:
                                results[niah_version_id] = {}

                            if niah_product_id not in results[niah_version_id]:
                                results[niah_version_id][niah_product_id] = []

                            if affected_version not in results[niah_version_id][niah_product_id]:
                                results[niah_version_id][niah_product_id].append(affected_version)
                        else:
                            cwe_ids = {}
                            cwe_ids['data'] = []
                            cwe_ids['data'].append(cweid)

                            references = {}
                            references['data'] = []
                            references['data'].append(reference)

                            description = {}
                            description['niah'] = vuln_name

                            baseMetricV3 = {}
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV3['baseScore'] = score

                            baseMetricV2 = {}
                            baseMetricV2['severity'] = severity
                            baseMetricV2['baseScore'] = score
                            
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
                            #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                            #    check = False
                            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                        else:
                            revision = '0'
                            self.niahid_entry[niahId] = {}
                            self.niahid_entry[niahId]['revision'] = '0'
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                        if check:
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                
                            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publishedDate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                                
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()

                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = revision
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision

                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                else:
                    data_id = "NIAH-JAVA-%s" % inc_no
                    data_type = "NOCVE"

                    niahId = "NIAH-%s-%s" % (data_type, inc_no)
                    niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % inc_no

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
                        #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                        #    check = False
                        self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                    else:
                        revision = '0'
                        self.niahid_entry[niahId] = {}
                        self.niahid_entry[niahId]['revision'] = '0'
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                    if check:
                        query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publisheddate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        if niah_version_id in self.versions_entry:
                            revision = int(self.versions_entry[niah_version_id]) + 1
                            self.versions_entry[niah_version_id] = revision
                        else:
                            revision = 0
                            self.versions_entry[niah_version_id] = revision

                        query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                        self.cursor.execute(query)
                        self.connection.commit() 
                            
                    inc_no = inc_no + 1


    def snyc_composer(self, date_update):
        with open("composer_vulns.json", "r") as f:
            json_data = json.load(f)

        application = "php"

        for data in json_data:
            packagename = data['packagename']
            home_url = data['home_url']
            vendor = data['vendor']
            product = data['product']
            
            if 'github' in data:
                github = data['github']
            else:
                github = ''

            type ="NVD"
            advisory = 'ADV'

            niah_product_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())
                
            if niah_product_id in self.product_entry:
                revision = int(self.product_entry[niah_product_id]) + 1
            else:
                revision = '0'
                    
            fetchData = self.check_productid_entry(niah_product_id)
                                        
            if fetchData:
                fetchData.sort(key=lambda x: x[5], reverse=True)
                res = fetchData[0][4]
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'composer'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
            else:
                res = {}
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'composer'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
                revision = '0'

            query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res), revision)
            self.cursor.execute(query)
            self.connection.commit()
            self.product_entry[niah_product_id] = revision
                
            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
            self.cursor.execute(query)
            self.connection.commit()

            inc_no = 1
            for vuln in tqdm(data['vulns']):
                vuln_name = vuln['vuln_name']
                vuln_name = vuln_name.replace("'", "")
                versions = vuln['versions']
                pub_date = vuln['pub_date']
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:
                    pass
                cves = vuln['cves']
                cweid = vuln['cweid']
                severity = vuln['severity']
                if severity.lower() == "moderate":
                    severity = "medium"
                severity = severity.upper()
                score = vuln['score']
                reference = vuln['reference']

                publishedDate = pub_date
                publisheddate = pub_date
                lastModifiedDate = pub_date
                
                affected_version = {}
                affected_version['product'] = product
                affected_version['vendor'] = vendor
                affected_version['patch'] = "upgrade latest version"
                affected_version['version'] = versions

                if not cves:
                    cves = []

                if len(cves) > 0:
                    for cve_id in cves:
                        results = {}
                        affected_products_versions = []
                        data_type = "CVE"
                        data_id = cve_id

                        niahId = "NIAH-%s-%s" % (data_type, data_id)
                        niah_version_id = "NIAH-VERSION-NVD-NIAH-%s" % data_id

                        fetchData = self.check_niahid_entry(niahId)
                        if fetchData:
                            fetchData.sort(key=lambda x: x[8], reverse=True)
                            cwe_ids = fetchData[0][0]
                            cwe_ids['data'].append(cweid)
                            references = fetchData[0][1]
                            references['data'].append(reference)
                            try:
                                description = fetchData[0][2]
                                description['niah'] = vuln_name
                            except:
                                description = {}
                                description['niah'] = vuln_name
                            baseMetricV3 = fetchData[0][3]
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV2 = fetchData[0][4]
                            baseMetricV2['severity'] = severity
                            publisheddate = fetchData[0][5]
                            lastModifiedDate = fetchData[0][6]
                            affected_products_versions = fetchData[0][7]
                            affected_products_versions.append(niah_version_id)
                            revision = fetchData[0][8] + 1

                            if niah_version_id not in results:
                                results[niah_version_id] = {}

                            if niah_product_id not in results[niah_version_id]:
                                results[niah_version_id][niah_product_id] = []

                            if affected_version not in results[niah_version_id][niah_product_id]:
                                results[niah_version_id][niah_product_id].append(affected_version)
                        else:
                            cwe_ids = {}
                            cwe_ids['data'] = []
                            cwe_ids['data'].append(cweid)

                            references = {}
                            references['data'] = []
                            references['data'].append(reference)

                            description = {}
                            description['niah'] = vuln_name

                            baseMetricV3 = {}
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV3['baseScore'] = score

                            baseMetricV2 = {}
                            baseMetricV2['severity'] = severity
                            baseMetricV2['baseScore'] = score
                            
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
                            #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                            #    check = False
                            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                        else:
                            revision = '0'
                            self.niahid_entry[niahId] = {}
                            self.niahid_entry[niahId]['revision'] = '0'
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                        if check:
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                
                            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publishedDate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                                
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()

                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = revision
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision

                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                else:
                    data_id = "NIAH-PHP-%s" % inc_no
                    data_type = "NOCVE"

                    niahId = "NIAH-%s-%s" % (data_type, inc_no)
                    niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % inc_no

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
                        #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                        #    check = False
                        self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                    else:
                        revision = '0'
                        self.niahid_entry[niahId] = {}
                        self.niahid_entry[niahId]['revision'] = '0'
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                    if check:
                        query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publisheddate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        if niah_version_id in self.versions_entry:
                            revision = int(self.versions_entry[niah_version_id]) + 1
                            self.versions_entry[niah_version_id] = revision
                        else:
                            revision = 0
                            self.versions_entry[niah_version_id] = revision

                        query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                        self.cursor.execute(query)
                        self.connection.commit() 
                            
                    inc_no = inc_no + 1

    def snyc_pip(self, date_update):
        with open("pip_vulns.json", "r") as f:
            json_data = json.load(f)

        application = "python"

        for data in json_data:
            packagename = data['packagename']
            home_url = data['home_url']
            vendor = data['vendor']
            product = data['product']
            
            if 'github' in data:
                github = data['github']
            else:
                github = ''

            type ="NVD"
            advisory = 'ADV'

            if product and vendor:
                niah_product_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())
            else:
                niah_product_id = "NIAH-NVD-ADV-%s" % (product.upper())

            if niah_product_id in self.product_entry:
                revision = int(self.product_entry[niah_product_id]) + 1
            else:
                revision = '0'
                    
            fetchData = self.check_productid_entry(niah_product_id)
                                        
            if fetchData:
                fetchData.sort(key=lambda x: x[5], reverse=True)
                res = fetchData[0][4]
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'pip'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
            else:
                res = {}
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'pip'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
                revision = '0'

            query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res), revision)
            self.cursor.execute(query)
            self.connection.commit()
            self.product_entry[niah_product_id] = revision
                
            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
            self.cursor.execute(query)
            self.connection.commit()

            inc_no = 1
            for vuln in tqdm(data['vulns']):
                vuln_name = vuln['vuln_name']
                vuln_name = vuln_name.replace("'", "")
                versions = vuln['versions']
                pub_date = vuln['pub_date']
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:
                    pass
                cves = vuln['cves']
                cweid = vuln['cweid']
                severity = vuln['severity']
                if severity.lower() == "moderate":
                    severity = "medium"
                severity = severity.upper()
                score = vuln['score']
                reference = vuln['reference']

                publishedDate = pub_date
                publisheddate = pub_date
                lastModifiedDate = pub_date
                
                affected_version = {}
                affected_version['product'] = product
                affected_version['vendor'] = vendor
                affected_version['patch'] = "upgrade latest version"
                affected_version['version'] = versions

                if not cves:
                    cves = []

                if len(cves) > 0:
                    for cve_id in cves:
                        results = {}
                        affected_products_versions = []
                        data_type = "CVE"
                        data_id = cve_id

                        niahId = "NIAH-%s-%s" % (data_type, data_id)
                        niah_version_id = "NIAH-VERSION-NVD-NIAH-%s" % data_id

                        fetchData = self.check_niahid_entry(niahId)
                        if fetchData:
                            fetchData.sort(key=lambda x: x[8], reverse=True)
                            cwe_ids = fetchData[0][0]
                            cwe_ids['data'].append(cweid)
                            references = fetchData[0][1]
                            references['data'].append(reference)
                            try:
                                description = fetchData[0][2]
                                description['niah'] = vuln_name
                            except:
                                description = {}
                                description['niah'] = vuln_name
                            baseMetricV3 = fetchData[0][3]
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV2 = fetchData[0][4]
                            baseMetricV2['severity'] = severity
                            publisheddate = fetchData[0][5]
                            lastModifiedDate = fetchData[0][6]
                            affected_products_versions = fetchData[0][7]
                            affected_products_versions.append(niah_version_id)
                            revision = fetchData[0][8] + 1

                            if niah_version_id not in results:
                                results[niah_version_id] = {}

                            if niah_product_id not in results[niah_version_id]:
                                results[niah_version_id][niah_product_id] = []

                            if affected_version not in results[niah_version_id][niah_product_id]:
                                results[niah_version_id][niah_product_id].append(affected_version)
                        else:
                            cwe_ids = {}
                            cwe_ids['data'] = []
                            cwe_ids['data'].append(cweid)

                            references = {}
                            references['data'] = []
                            references['data'].append(reference)

                            description = {}
                            description['niah'] = vuln_name

                            baseMetricV3 = {}
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV3['baseScore'] = score

                            baseMetricV2 = {}
                            baseMetricV2['severity'] = severity
                            baseMetricV2['baseScore'] = score
                            
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
                            #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                            #    check = False
                            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                        else:
                            revision = '0'
                            self.niahid_entry[niahId] = {}
                            self.niahid_entry[niahId]['revision'] = '0'
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                        if check:
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                
                            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publishedDate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                                
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()

                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = revision
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision

                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                else:
                    data_id = "NIAH-PYTHON-%s" % inc_no
                    data_type = "NOCVE"

                    niahId = "NIAH-%s-%s" % (data_type, inc_no)
                    niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % inc_no

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
                        #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                        #    check = False
                        self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                    else:
                        revision = '0'
                        self.niahid_entry[niahId] = {}
                        self.niahid_entry[niahId]['revision'] = '0'
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                    if check:
                        query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publisheddate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        if niah_version_id in self.versions_entry:
                            revision = int(self.versions_entry[niah_version_id]) + 1
                            self.versions_entry[niah_version_id] = revision
                        else:
                            revision = 0
                            self.versions_entry[niah_version_id] = revision

                        query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                        self.cursor.execute(query)
                        self.connection.commit() 
                            
                    inc_no = inc_no + 1

    def snyc_npm(self, date_update):
        with open("npm_vulns.json", "r") as f:
            json_data = json.load(f)

        application = "javascript"

        for data in json_data:
            packagename = data['packagename']
            home_url = data['home_url']
            vendor = data['vendor']
            product = data['product']
            
            if 'github' in data:
                github = data['github']
            else:
                github = ''

            type ="NVD"
            advisory = 'ADV'

            if product and vendor:
                niah_product_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())
            else:
                niah_product_id = "NIAH-NVD-ADV-%s" % (product.upper())

            if niah_product_id in self.product_entry:
                revision = int(self.product_entry[niah_product_id]) + 1
            else:
                revision = '0'
                    
            fetchData = self.check_productid_entry(niah_product_id)
                                        
            if fetchData:
                fetchData.sort(key=lambda x: x[5], reverse=True)
                res = fetchData[0][4]
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'npm'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
            else:
                res = {}
                res['language'] = application
                res['part'] = 'a'
                res['installer'] = 'npm'
                res['installer_view'] = home_url
                if github:
                    res['github'] = github
                res['packagename'] = packagename
                revision = '0'

            query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(res), revision)
            self.cursor.execute(query)
            self.connection.commit()
            self.product_entry[niah_product_id] = revision
                
            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_product_id, 'indev', date_update, '0')
            self.cursor.execute(query)
            self.connection.commit()

            inc_no = 1
            for vuln in tqdm(data['vulns']):
                vuln_name = vuln['vuln_name']
                vuln_name = vuln_name.replace("'", "")
                versions = vuln['versions']
                pub_date = vuln['pub_date']
                try:
                    res1 = dateConvert()
                    pub_date = res1.dateCon(pub_date)
                except:
                    pass
                cves = vuln['cves']
                cweid = vuln['cweid']
                severity = vuln['severity']
                if severity.lower() == "moderate":
                    severity = "medium"
                severity = severity.upper()
                score = vuln['score']
                reference = vuln['reference']

                publishedDate = pub_date
                publisheddate = pub_date
                lastModifiedDate = pub_date
                
                affected_version = {}
                affected_version['product'] = product
                affected_version['vendor'] = vendor
                affected_version['patch'] = "upgrade latest version"
                affected_version['version'] = versions

                if not cves:
                    cves = []

                if len(cves) > 0:
                    for cve_id in cves:
                        results = {}
                        affected_products_versions = []
                        data_type = "CVE"
                        data_id = cve_id

                        niahId = "NIAH-%s-%s" % (data_type, data_id)
                        niah_version_id = "NIAH-VERSION-NVD-NIAH-%s" % data_id

                        fetchData = self.check_niahid_entry(niahId)
                        if fetchData:
                            fetchData.sort(key=lambda x: x[8], reverse=True)
                            cwe_ids = fetchData[0][0]
                            cwe_ids['data'].append(cweid)
                            references = fetchData[0][1]
                            references['data'].append(reference)
                            try:
                                description = fetchData[0][2]
                                description['niah'] = vuln_name
                            except:
                                description = {}
                                description['niah'] = vuln_name
                            baseMetricV3 = fetchData[0][3]
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV2 = fetchData[0][4]
                            baseMetricV2['severity'] = severity
                            publisheddate = fetchData[0][5]
                            lastModifiedDate = fetchData[0][6]
                            affected_products_versions = fetchData[0][7]
                            affected_products_versions.append(niah_version_id)
                            revision = fetchData[0][8] + 1

                            if niah_version_id not in results:
                                results[niah_version_id] = {}

                            if niah_product_id not in results[niah_version_id]:
                                results[niah_version_id][niah_product_id] = []

                            if affected_version not in results[niah_version_id][niah_product_id]:
                                results[niah_version_id][niah_product_id].append(affected_version)
                        else:
                            cwe_ids = {}
                            cwe_ids['data'] = []
                            cwe_ids['data'].append(cweid)

                            references = {}
                            references['data'] = []
                            references['data'].append(reference)

                            description = {}
                            description['niah'] = vuln_name

                            baseMetricV3 = {}
                            baseMetricV3['baseSeverity'] = severity
                            baseMetricV3['baseScore'] = score

                            baseMetricV2 = {}
                            baseMetricV2['severity'] = severity
                            baseMetricV2['baseScore'] = score
                            
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
                            #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                            #    check = False
                            self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                        else:
                            revision = '0'
                            self.niahid_entry[niahId] = {}
                            self.niahid_entry[niahId]['revision'] = '0'
                            self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                        if check:
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                
                            query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publishedDate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                                
                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()

                            query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()

                            if niah_version_id in self.versions_entry:
                                revision = int(self.versions_entry[niah_version_id]) + 1
                                self.versions_entry[niah_version_id] = revision
                            else:
                                revision = 0
                                self.versions_entry[niah_version_id] = revision

                            self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
                            self.cursor = self.connection.cursor()
                            query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                            #print(query)
                            self.cursor.execute(query)
                            self.connection.commit()
                else:
                    data_id = "NIAH-JAVASCRIPT-%s" % inc_no
                    data_type = "NOCVE"

                    niahId = "NIAH-%s-%s" % (data_type, inc_no)
                    niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % inc_no

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
                        #if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                        #    check = False
                        self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate
                    else:
                        revision = '0'
                        self.niahid_entry[niahId] = {}
                        self.niahid_entry[niahId]['revision'] = '0'
                        self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                    if check:
                        query = "INSERT INTO vuln_tab(niahid, data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision)VALUES('{niahId}', '{data_type}', '{data_id}', '{cwe_ids}', '{references}', '{description}', '{baseMetricV3}', '{baseMetricV2}', '{publishedDate}', '{lastModifiedDate}', '{affected_products_versions}', '1', 'indev', '{revision}');".format(niahId=niahId, data_type=data_type, data_id=data_id, cwe_ids=json.dumps(cwe_ids), references=json.dumps(references), description=json.dumps(description), baseMetricV2=json.dumps(baseMetricV2), baseMetricV3=json.dumps(baseMetricV3), publishedDate=publisheddate, lastModifiedDate=lastModifiedDate, affected_products_versions=json.dumps(affected_products_versions), revision=revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'cve', niahId, 'indev', date_update, revision)
                        self.cursor.execute(query)
                        self.connection.commit()

                        if niah_version_id in self.versions_entry:
                            revision = int(self.versions_entry[niah_version_id]) + 1
                            self.versions_entry[niah_version_id] = revision
                        else:
                            revision = 0
                            self.versions_entry[niah_version_id] = revision

                        query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision) values('%s', '%s', '%s')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                        self.cursor.execute(query)
                        self.connection.commit() 
                            
                    inc_no = inc_no + 1

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = snyk_db()
    #res.snyc_npm(date_update)
    #res.snyc_pip(date_update)
    #res.snyc_composer(date_update)
    res.snyc_maven(date_update)