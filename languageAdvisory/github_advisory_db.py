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
        query = "select cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, revision from vuln_tab where niahid='%s'" % niahId
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

    def getIssueDetails(self, url):
        try:
            page = requests.get(url)
            soup = BeautifulSoup(page.content, "html.parser")        
            divBd = soup.findAll('div', {'class':'Box-body'})[0]
            divRw = divBd.findAll('div', {'class':'Bow-row border-0 clearfix'})[0]
        except:
            time.sleep(60)
            page = requests.get(url)
            soup = BeautifulSoup(page.content, "html.parser")        
            divBd = soup.findAll('div', {'class':'Box-body'})[0]
            divRw = divBd.findAll('div', {'class':'Bow-row border-0 clearfix'})[0]
        
        if soup.findAll('span', {'class': 'Label Label--warning text-bold mr-1 v-align-middle'}):
            severity = soup.findAll('span', {'class': 'Label Label--warning text-bold mr-1 v-align-middle'})
            severity = severity[0].text.strip()
            severity = severity.replace(" severity", "")
        elif soup.findAll('span', {'class': 'Label Label--orange text-bold mr-1 v-align-middle'}):
            severity = soup.findAll('span', {'class': 'Label Label--orange text-bold mr-1 v-align-middle'})
            severity = severity[0].text.strip()
            severity = severity.replace(" severity", "")
        
        results = {}
        product = ''
        application = ''
        versions = []
        patches = []
        cves = []
        severity = ''
        pub_date = ''
        lastupdate_date = ''
        vuln_name = ''
        cwe_id = ''

        if re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE):
            cves = re.findall(r'(CVE-\d+-\d+)', str(soup), re.IGNORECASE)
            cves = self.uniqCVEs(cves)

        if re.findall(r'(CWE-\d+)', str(soup), re.IGNORECASE):
            cwe_id = re.findall(r'(CWE-\d+)', str(soup), re.IGNORECASE)[0]

        if soup.findAll('span', {'class':'Label Label--warning text-bold mr-1 v-align-middle'}):
            severity = soup.findAll('span', {'class':'Label Label--warning text-bold mr-1 v-align-middle'})[0].text.strip()
            if re.findall(r'(.*)\sseverity', str(severity)):
                severity = re.findall(r'(.*)\sseverity', str(severity))[0]
                if severity == "moderate":
                    severity = "medium"

        if soup.findAll('span', {'class':'Label Label--orange text-bold mr-1 v-align-middle'}):
            severity = soup.findAll('span', {'class':'Label Label--orange text-bold mr-1 v-align-middle'})[0].text.strip()
            if re.findall(r'(.*)\sseverity', str(severity)):
                severity = re.findall(r'(.*)\sseverity', str(severity))[0]
                if severity == "moderate":
                    severity = "medium"

        pub_date = soup.findAll('relative-time')[0].text
        res1 = dateConvert()
        pub_date = res1.dateCon(pub_date)

        if re.findall(r'relative-time datetime=\"(.*?)\"', str(soup)):
            pub_date = re.findall(r'relative-time datetime=\"(.*?)\"', str(soup))[0]
            res1 = dateConvert()
            pub_date = res1.dateCon(pub_date)

            lastupdate_date = re.findall(r'relative-time datetime=\"(.*?)\"', str(soup))[1]
            res1 = dateConvert()
            lastupdate_date = res1.dateCon(lastupdate_date)


        if soup.findAll('h2', {'class':'lh-condensed Subhead-heading '}):
            vuln_name = soup.findAll('h2', {'class':'lh-condensed Subhead-heading '})[0].text
        elif soup.findAll('h2', {'class': 'lh-condensed Subhead-heading'}):
            description = soup.findAll('h2', {'class': 'lh-condensed Subhead-heading'})
            vuln_name = description[0].text.strip()
        else:
            vuln_name = ''


        for div in divRw.findAll('div'):
            if "Package" in str(div):
                if div.findAll('span', {'class':'text-gray-dark text-bold f4'}):
                    product = div.findAll('span', {'class':'text-gray-dark text-bold f4'})[0].text
                elif div.findAll('span', {'class':'color-text-primary text-bold f4'}):
                    product = div.findAll('span', {'class':'color-text-primary text-bold f4'})[0].text
                elif div.findAll('span', {'class':'f4 color-text-primary text-bold'}):
                    product = div.findAll('span', {'class':'f4 color-text-primary text-bold'})[0].text
                elif div.findAll('span', {'class': "f4 color-fg-default text-bold"}):
                    product = div.findAll('span', {'class': "f4 color-fg-default text-bold"})[0].text
                else:
                    print("[ OK ] Product not found")
                    sys.exit(1)

                if div.findAll('span', {'class':'text-gray f4'}):
                    application = div.findAll('span', {'class':'text-gray f4'})[0].text
                elif div.findAll('span', {'class':'color-text-secondary f4'}):
                    application = div.findAll('span', {'class':'color-text-secondary f4'})[0].text
                elif div.findAll('span', {'class':'color-fg-muted f4'}):
                    application = div.findAll('span', {'class':'color-fg-muted f4'})[0].text
                else:
                    print("[ OK ] Application not found")
                    sys.exit(1)

                
                application = re.sub(r'\n', '', str(application))
                application = re.sub(r'\s+', '', str(application))

                if re.findall(r'\((.*)\)', str(application)):
                    application = re.findall(r'\((.*)\)', str(application))[0]
                elif re.findall(r'\(\n\s+(.*)\n\n\)', str(application)):
                    application = re.findall(r'\(\n\s+(.*)\n\n\)', str(application))[0]

                application = application.lower()

            if 'Affected versions' in str(div):
                if div.findAll('div', {'class':'text-bold text-gray-dark f4'}):
                    for vers in div.findAll('div', {'class':'text-bold text-gray-dark f4'}):
                        versionStr = vers.text

                        verss = versionStr.split(",")

                        if len(verss) == 1:
                            version = verss[0].strip()
                            if re.findall(r'>=\s+(\d.+)', str(version)):
                                version = "*"
                            elif re.findall(r'<=\s+(\d.+)', str(version)):
                                version = "[0.0:%s]" % re.findall(r'<=\s+(\d.+)', str(version))[0]
                            elif re.findall(r'<\s+(\d.+)', str(version)):
                                version = "[0.0:%s)" % re.findall(r'<\s+(\d.+)', str(version))[0]
                            else:
                                version = version

                            versions.append(version)
                        
                        if len(verss) > 1:
                            version = ''
                            if re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "[%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "(%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "(%s:%s]" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "[%s:%s]" % (ver[0][0], ver[0][1])

                            versions.append(version)

                if div.findAll('div', {'class':'f4 color-fg-default text-bold'}):
                    for vers in div.findAll('div', {'class':'f4 color-fg-default text-bold'}):
                        versionStr = vers.text

                        verss = versionStr.split(",")

                        if len(verss) == 1:
                            version = verss[0].strip()
                            if re.findall(r'>=\s+(\d.+)', str(version)):
                                version = "*"
                            elif re.findall(r'<=\s+(\d.+)', str(version)):
                                version = "[0.0:%s]" % re.findall(r'<=\s+(\d.+)', str(version))[0]
                            elif re.findall(r'<\s+(\d.+)', str(version)):
                                version = "[0.0:%s)" % re.findall(r'<\s+(\d.+)', str(version))[0]
                            else:
                                version = version

                            versions.append(version)
                        
                        if len(verss) > 1:
                            version = ''
                            if re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "[%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "(%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "(%s:%s]" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "[%s:%s]" % (ver[0][0], ver[0][1])

                            versions.append(version)

                if div.findAll('div', {'class':'f4 color-text-primary text-bold'}):
                    for vers in div.findAll('div', {'class':'f4 color-text-primary text-bold'}):
                        versionStr = vers.text

                        verss = versionStr.split(",")

                        if len(verss) == 1:
                            version = verss[0].strip()
                            if re.findall(r'>=\s+(\d.+)', str(version)):
                                version = "*"
                            elif re.findall(r'<=\s+(\d.+)', str(version)):
                                version = "[0.0:%s]" % re.findall(r'<=\s+(\d.+)', str(version))[0]
                            elif re.findall(r'<\s+(\d.+)', str(version)):
                                version = "[0.0:%s)" % re.findall(r'<\s+(\d.+)', str(version))[0]
                            elif re.findall(r'=\s+(\d.+)', str(version)):
                                version = "%s" % re.findall(r'=\s+(\d.+)', str(version))[0]
                            else:
                                version = version

                            versions.append(version)
                        
                        if len(verss) > 1:
                            version = ''
                            if re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "[%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<\s+(.*)', str(versionStr))
                                version = "(%s:%s)" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "(%s:%s]" % (ver[0][0], ver[0][1])
                            elif re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr)):
                                ver= re.findall(r'>=\s(.*),\s+<=\s+(.*)', str(versionStr))
                                version = "[%s:%s]" % (ver[0][0], ver[0][1])

                            versions.append(version)

            if 'Patched versions' in str(div):
                if div.findAll('div', {'class':'text-gray-dark text-bold f4'}):
                    for pt in div.findAll('div', {'class':'text-gray-dark text-bold f4'}):
                        patch = "Upgrade to version %s" % pt.text
                        patches.append(patch)
                elif div.findAll('div', {'class':'text-gray f4'}):
                    for pt in div.findAll('div', {'class':'text-gray f4'}):
                        patch = "Upgrade to version %s" % pt.text
                        patches.append(patch)
                elif div.findAll('div', {'class':'f4 color-text-primary text-bold'}):
                    for pt in div.findAll('div', {'class':'f4 color-text-primary text-bold'}):
                        patch = "Upgrade to version %s" % pt.text
                        patches.append(patch)
                elif div.findAll('div', {'class':'f4 color-fg-default text-bold'}):
                    for pt in div.findAll('div', {'class':'f4 color-fg-default text-bold'}):
                        patch = "Upgrade to version %s" % pt.text
                        patches.append(patch)

        if len(versions) > 0:
            results['versions'] = ','.join(versions)
        else:
            results['versions'] = ''
        results['product'] = str(product)
        results['application'] = str(application)
        if len(patches) > 0:
            results['patch'] = ','.join(patches)
        else:
            results['patch'] = ''
        results['cves'] = cves
        results['cwe_id'] = cwe_id
        results['severity'] = severity
        results['pub_date'] = pub_date
        results['lastupdate_date'] = lastupdate_date
        results['vuln_name'] = vuln_name

        return results

    def get_next_num(self):
        query = "select max(id) from vuln_tab"
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()
        return fetchData[0][0] + 1

    def initialize(self, date_update):
        print("[ OK ] GHSAdvisory Sync Started")

        i = 0
        while True:
            print(i)
            time.sleep(5)
            if self.daily:
                if i == 1:
                    break
            advUrl = "https://github.com/advisories?page=%s" % i
            page = requests.get(advUrl)
            soup = BeautifulSoup(page.content, "html.parser")

            if re.findall(r'No results matched your search', str(soup)):
                break

            if re.findall(r'\/advisories\/(GHSA-.*?)\"', str(soup)):
                for ghsa_id in tqdm(re.findall(r'\/advisories\/(GHSA-.*?)\"', str(soup))):
                    url = "https://github.com/advisories/%s" % ghsa_id
                    results = self.getIssueDetails(url)

                    cves = results['cves']
                    cwe_text = results['cwe_id']
                    versions = results['versions']
                    application = results['application']
                    patch = results['patch']
                    severity = results['severity']
                    if severity.lower() == "moderate":
                        severity = "medium"
                    severity = severity.lower()
                    publisheddate = results['pub_date']
                    lastModifiedDate = results['lastupdate_date']
                    product = results['product']
                    vuln_name = results['vuln_name']
                    vuln_name = vuln_name.replace("'", "")
                    vendor = ''
                    groupId = ''
                    artifactId = ''

                    if application == "maven" or application == "Maven":
                        groupId = product.split(":")[0]
                        artifactId = product.split(":")[1]
                        application = "java"
                    elif application == "composer" or application == "Composer":
                        application = "php"
                        if "/" in product:
                            product = product.split("/")[1]
                            vendor = product.split("/")[0]
                    elif application == "npm" or application == "Npm":
                        application = "javascript"
                        if "/" in product:
                            product = product.split("/")[1]
                            vendor = product.split("/")[0]
                    elif application == "pip" or application == "pypi" or application == "PIP" or application == "Pip" or application == "Pypi":
                        application = "python"
                    elif application == "NuGet":
                        application = "dotnet"
                    elif application == "RubyGems":
                        application = "ruby"
                    elif application == "Go":
                        application = "golang"
                    elif application == "Rust":
                        application = "rust"

                    cwe_ids = {}
                    cwe_ids['data'] = []
                    cwe_ids['data'].append(cwe_text)

                    references = {}
                    references['data'] = []
                    references['data'].append(url)

                    description = {}
                    description['nvd'] = vuln_name

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

                        message = "(NIAH-PRODUCT-ID : %s) product: %s and vendor: %s updated" % (niah_product_id, product, vendor)
                        res = check_alerts()
                        res.update_alerts('product', niah_product_id, date_update, message)


                    if len(cves) > 0:
                        for cve_id in cves:
                            affected_products_versions = []
                            results = {}

                            data_id = cve_id
                            data_type = "CVE"

                            niahId = "NIAH-%s-%s" % (data_type, data_id)
                            niah_version_id = "NIAH-VERSION-NVD-GHSA-%s" % data_id
            
                            fetchData = self.check_niahid_entry(niahId)
                            if fetchData:
                                fetchData.sort(key=lambda x: x[8], reverse=True)
                                cwe_ids = fetchData[0][0]
                                if cwe_text:
                                    cwe_ids['data'].append(cwe_text)
                                references = fetchData[0][1]
                                if url:
                                    references['data'].append(url)
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
                                cwe_ids = {}
                                cwe_ids['data'] = []
                                cwe_ids['data'].append(cwe_text)

                                references = {}
                                references['data'] = []
                                references['data'].append(url)

                                description = {}
                                description['nvd'] = vuln_name

                                baseMetricV3 = {}
                                baseMetricV3['baseSeverity'] = severity
                                baseMetricV2 = {}
                                baseMetricV2['severity'] = severity

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

                                message = "(NIAH-VULN-ID : %s) %s CVE updated" % (niahId, data_id)
                                res = check_alerts()
                                res.update_alerts('cve_id', data_id, date_update, message)
                                
                    else:
                        data_id = ghsa_id
                        data_type = "NOCVE"

                        niahId = "NIAH-%s-%s" % (data_type, ghsa_id)
                        niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % ghsa_id

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

                            message = "(NIAH-VULN-ID : %s) %s CVE updated" % (niahId, data_id)
                            res = check_alerts()
                            res.update_alerts('cve_id', data_id, date_update, message)


            i = i + 1
            
        print("[ OK ] GHSAdvisory Sync Completed")

            
if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = GHSAdvisory()
    res.initialize(date_update)
    #url = "https://github.com/advisories/GHSA-5vjc-qx43-r747"
    #res.getIssueDetails(url)
