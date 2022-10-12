from email import message
import sys
import os.path
from os import path
import collections
from typing import Reversible
from tqdm import tqdm
import datetime
import re
import datetime
import subprocess
import os
import configparser
import ast
import datetime
import time
import json
from collections import defaultdict
import sys
from itertools import groupby
from operator import itemgetter, ne
from pprint import pprint
from itertools import chain  
from lib.dateConvert import dateConvert
import json
import psycopg2
from lib.alearts_manage import check_alerts
import sqlite3
from pathlib import Path


"""
CREATE TABLE vuln_tab(id SERIAL PRIMARY KEY, niahid TEXT UNIQUE, data_type VARCHAR(20), data_id VARCHAR(20), cwe_data jsonb, reference_data jsonb, description jsonb, basemetricv3_data jsonb, basemetricv2_data jsonb, publisheddate VARCHAR(20), lastmodifieddate VARCHAR(20), affected_products_versions jsonb, status VARCHAR(100));
CREATE TABLE affected_versions_tab(id SERIAL PRIMARY KEY, niah_version_id TEXT, niah_product_id TEXT, versions jsonb);
CREATE TABLE product_reference_tab(id SERIAL PRIMARY KEY, niah_product_id TEXT, product TEXT, vendor TEXT, advisory VARCHAR(200), type VARCHAR(200), data jsonb);


create table alerttabs(id SERIAL PRIMARY KEY, company_id text, team_id text, user_id text, alert_type text, alert_name text, alert_mode text, status VARCHAR(100), messages jsonb, last_update VARCHAR(200));

#NEW
CREATE TABLE vuln_tab(id SERIAL PRIMARY KEY, niahid TEXT UNIQUE, data_type VARCHAR(20), data_id TEXT, cwe_data jsonb, reference_data jsonb, description jsonb, basemetricv3_data jsonb, basemetricv2_data jsonb, publisheddate VARCHAR(50), lastmodifieddate VARCHAR(50), affected_products_versions jsonb, status VARCHAR(100), vuln_status VARCHAR(100), revision int UNIQUE);
CREATE TABLE affected_versions_tab(id SERIAL PRIMARY KEY, niah_version_id TEXT, versions jsonb, revision int, vuln_status VARCHAR(100));
CREATE TABLE product_reference_tab(id SERIAL PRIMARY KEY, niah_product_id TEXT, product TEXT, vendor TEXT, advisory VARCHAR(200), type VARCHAR(200), data jsonb, revision int, vuln_status VARCHAR(100));
ALTER TABLE vuln_tab ADD CONSTRAINT vuln_tab_id UNIQUE (revision, niahid);
ALTER TABLE vuln_tab DROP CONSTRAINT vuln_tab_niahid_key;
ALTER TABLE vuln_tab DROP CONSTRAINT vuln_tab_revision_key;
ALTER TABLE product_reference_tab ADD CONSTRAINT niah_product_id UNIQUE (niah_product_id, revision);
ALTER TABLE affected_versions_tab ADD CONSTRAINT niah_version_id UNIQUE (niah_version_id, revision);
CREATE TABLE history(id SERIAL PRIMARY KEY, username VARCHAR(200), type VARCHAR(100), niahid TEXT, status VARCHAR(100), lastupdated VARCHAR(100), revision int);

in API:
CREATE TABLE task_manager(id SERIAL PRIMARY KEY, user_id text, projectid text, res_id text)

"""



class nvdGet():
    def __init__(self, date_update):
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        self.hostName = self.settings.get('database', 'host')
        self.userName = self.settings.get('database', 'user')
        self.password = self.settings.get('database', 'pass')
        self.databaseName = self.settings.get('database', 'dbname')

        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()

        self.date_update = date_update

        sys.setrecursionlimit(100000)

        self.cleanup()

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


        if self.daily:
            fileLists = self.get_nvd_data_daily()
            for data in fileLists:
                year = data['year']
                filename = data['filename']

                print("[ OK ] %s started" % filename)
                self.initialize(year, filename)
        else:
            fileLists = self.get_nvd_data_first()
            for data in fileLists:
                year = data['year']
                filename = data['filename']
                print("[ OK ] %s year started" % year)
                self.initialize(year, filename)



    def cleanup(self):
        #Removes NVD feeds
        os.system("rm -rf NVD/*")
        pass

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

    def get_nvd_data_daily(self):
        fileLists = []
        os.chdir("NVD")
        os.system("rm -rf NVD/nvdcve-1.1-recent*")
        os.system("rm -rf NVD/nvdcve-1.1-modified*")

        recent_xml = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
        modified_xml = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"

        subprocess.call("wget " + recent_xml, shell=True)
        fname = "nvdcve-1.1-recent.json.gz"
        subprocess.call("7z x %s" % fname, shell=True)
        subprocess.call("wget " + modified_xml, shell=True)
        fname = "nvdcve-1.1-modified.json.gz"
        subprocess.call("7z x %s" % fname, shell=True)

        #fileLists.append('nvdcve-1.1-recent.json')
        #fileLists.append('nvdcve-1.1-modified.json')

        res = {}
        res['year'] = datetime.datetime.now().year
        res['filename'] = 'nvdcve-1.1-recent.json'
        fileLists.append(res)

        res = {}
        res['year'] = datetime.datetime.now().year
        res['filename'] = 'nvdcve-1.1-modified.json'
        fileLists.append(res)

        os.chdir("..")
        return fileLists

    def get_next_num_version(self):
        try:
            query = "select max(id) from affected_versions_tab"
            self.cursor.execute(query)
            fetchData = self.cursor.fetchall()
            return fetchData[0][0] + 1
        except:
            return 0

    def get_nvd_data_first(self):
        fileLists = []
        year = datetime.datetime.now().year
        os.chdir("NVD")
        
        while year >= 2002:
                fname = "nvdcve-1.1-" + str(year) + ".json.gz"
                url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(year) + ".json.gz"
                subprocess.call("wget " + url, shell=True)
                subprocess.call("7z x %s" % fname, shell=True)
                year -= 1
                res = {}
                res['year'] = year
                res['filename'] = fname.replace(".gz", "")
                fileLists.append(res)
    
        os.chdir("..")
        return fileLists

    def check_product_entry(self, niahId):
        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()
        query = "select * from product_reference_tab where niah_product_id='%s'" % niahId
        #self.connection = psycopg2.connect(user=self.userName,password=self.password,host=self.hostName,port="5432",database=self.databaseName)
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()
        if len(fetchData) > 0:
            return False
        else:
            return True

    def initialize(self, year, filename):
        update_filename = "/var/DB/feeds/updated/%s.json" % datetime.datetime.today().strftime('%Y-%m-%d').replace("-", "_")

        update_filename_path = Path(update_filename)
        if update_filename_path.is_file():
            with open(update_filename, "r") as f:
                updated_cves = json.load(f)
        else:
            updated_cves = {}
            updated_cves['product_ids'] = []
            updated_cves['niah_ids'] = []

        all_cves = []

        fileData = open("NVD/%s" % filename, "r")
        cve_dict = json.load(fileData)

        date_update = cve_dict['CVE_data_timestamp']

        all_cves = all_cves + cve_dict['CVE_Items']
        
        for cves in tqdm(all_cves):
            results = {}

            data_type = cves['cve']['data_type']
            data_id = cves['cve']['CVE_data_meta']['ID']
            publishedDate = cves['publishedDate']
            lastModifiedDate = cves['lastModifiedDate']
            niahId = "NIAH-%s-%s" % (data_type, data_id)
            
            niah_version_id = "NIAH-VERSION-NVD-ADV-%s" % data_id
            if niah_version_id not in results:
                results[niah_version_id] = {}

            tags = []

            cwe_ids = {}
            cwe_ids['data'] = []
            if 'problemtype' in cves['cve']:
                for problem_type in cves['cve']['problemtype']['problemtype_data']:
                    for descr in problem_type['description']:
                        cwe_id =  descr['value']
                        cwe_ids['data'].append(cwe_id)
        
            references = {}
            references['data'] = []
            if 'references' in cves['cve']:
                if 'reference_data' in cves['cve']['references']:
                    for reference in cves['cve']['references']['reference_data']:
                        refe = reference['url']
                        refe = refe.replace("'", "")
                        references['data'].append(refe)

            description = {}
            if 'description' in cves['cve']:
                for desc in cves['cve']['description']['description_data']:
                    if desc['lang'] == "en":
                        desc = desc['value']
                        desc = desc.replace("'", "")
            else:
                desc = ''

            description['nvd'] = desc
            
            baseMetricV3 = {}
            if 'impact' in cves:
                if 'baseMetricV3' in cves['impact']:
                    if 'cvssV3' in cves['impact']['baseMetricV3']:
                        if 'attackComplexity' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['attackComplexity'] = cves['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                        if 'attackVector' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['attackVector'] = cves['impact']['baseMetricV3']['cvssV3']['attackVector']
                        if 'availabilityImpact' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['availabilityImpact'] = cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
                        if 'confidentialityImpact' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['confidentialityImpact'] = cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                        if 'integrityImpact' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['integrityImpact'] = cves['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                        if 'privilegesRequired' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['privilegesRequired'] = cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                        if 'scope' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['scope'] = cves['impact']['baseMetricV3']['cvssV3']['scope']
                        if 'userInteraction' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['userInteraction'] = cves['impact']['baseMetricV3']['cvssV3']['userInteraction']
                        if 'vectorString' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['vectorString'] = cves['impact']['baseMetricV3']['cvssV3']['vectorString']
                        if 'exploitabilityScore' in cves['impact']['baseMetricV3']:
                            baseMetricV3['exploitabilityScore'] = str(cves['impact']['baseMetricV3']['exploitabilityScore'])
                        if 'impactScore' in cves['impact']['baseMetricV3']:
                            baseMetricV3['impactScore'] = str(cves['impact']['baseMetricV3']['impactScore'])
                        if 'baseScore' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['baseScore'] = str(cves['impact']['baseMetricV3']['cvssV3']['baseScore'])
                        if 'baseSeverity' in cves['impact']['baseMetricV3']['cvssV3']:
                            baseMetricV3['baseSeverity'] = str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity'])

            baseMetricV2 = {}   
            if 'impact' in cves:
                if 'baseMetricV2' in cves['impact']:
                    if 'cvssV2' in cves['impact']['baseMetricV2']:
                        if 'accessComplexity' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['accessComplexity'] = cves['impact']['baseMetricV2']['cvssV2']['accessComplexity']
                        if 'accessComplexity' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['accessVector'] = cves['impact']['baseMetricV2']['cvssV2']['accessVector']
                        if 'authentication' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['authentication'] = cves['impact']['baseMetricV2']['cvssV2']['authentication']
                        if 'availabilityImpact' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['availabilityImpact'] = cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
                        if 'confidentialityImpact' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['confidentialityImpact'] = cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
                        if 'integrityImpact' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['integrityImpact'] = cves['impact']['baseMetricV2']['cvssV2']['integrityImpact']
                        if 'obtainAllPrivilege' in cves['impact']['baseMetricV2']:
                            baseMetricV2['obtainAllPrivilege'] = str(cves['impact']['baseMetricV2']['obtainAllPrivilege'])
                        if 'obtainOtherPrivilege' in cves['impact']['baseMetricV2']:
                            baseMetricV2['obtainOtherPrivilege'] = str(cves['impact']['baseMetricV2']['obtainOtherPrivilege'])
                        if 'obtainUserPrivilege' in cves['impact']['baseMetricV2']:
                            baseMetricV2['obtainUserPrivilege'] = str(cves['impact']['baseMetricV2']['obtainUserPrivilege'])
                        if 'obtainUserPrivilege' in cves['impact']['baseMetricV2']:
                            baseMetricV2['obtainUserPrivilege'] = str(cves['impact']['baseMetricV2']['obtainUserPrivilege'])
                        if 'userInteractionRequired' in cves['impact']['baseMetricV2']:
                            baseMetricV2['userInteractionRequired'] = str(cves['impact']['baseMetricV2']['userInteractionRequired'])
                        if 'vectorString' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['vectorString'] = cves['impact']['baseMetricV2']['cvssV2']['vectorString']
                        if 'exploitabilityScore' in str(cves['impact']['baseMetricV2']):
                            baseMetricV2['exploitabilityScore'] = str(cves['impact']['baseMetricV2']['exploitabilityScore'])
                        if 'impactScore' in cves['impact']['baseMetricV2']:
                            baseMetricV2['impactScore'] = str(cves['impact']['baseMetricV2']['impactScore'])
                        if 'baseScore' in cves['impact']['baseMetricV2']['cvssV2']:
                            baseMetricV2['baseScore'] = str(cves['impact']['baseMetricV2']['cvssV2']['baseScore'])
                        if 'severity' in cves['impact']['baseMetricV2']:
                            baseMetricV2['severity'] = str(cves['impact']['baseMetricV2']['severity'])


            details = {}
            details['data'] = []


            affected_products_versions = []
            
            if 'configurations' in cves:
                if 'nodes' in cves['configurations']:
                    for node in cves['configurations']['nodes']:
                        if 'children' in node and len(node['children']) > 0:
                            for chld in node['children']:
                                for cpe in chld['cpe_match']:
                                    vulnerable = cpe['vulnerable']
                                    cpe23Uri = cpe['cpe23Uri']
                                    check = True

                                    if re.findall(r'cpe:2\.3:(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?)', str(cpe23Uri)):
                                        cpe_data = re.findall(r'cpe:2\.3:(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?)', str(cpe23Uri))[0]
                                        part = cpe_data[0]
                                        vendor = cpe_data[1]
                                        product = cpe_data[2]
                                        version = cpe_data[3]
                                        update = cpe_data[4]
                                        edition = cpe_data[5]
                                        language = cpe_data[6]
                                        software_edition = cpe_data[7]
                                        target_software = cpe_data[8]
                                        target_hardware = cpe_data[9]
                                        other = cpe_data[10]
                                    elif re.findall(r'cpe:\/(.*?):(.*?):(.*?):(.*?):(.*)', str(cpe23Uri)):
                                        cpe_data = re.findall(r'cpe:\/(.*?):(.*?):(.*?):(.*?):(.*)', str(cpe23Uri))[0]
                                        part = cpe_data[0]
                                        vendor = cpe_data[1]
                                        product = cpe_data[2]
                                        version = cpe_data[3]
                                        update = cpe_data[4]
                                        edition = ''
                                        language = ''
                                        software_edition = ''
                                        target_software = ''
                                        target_hardware = ''
                                        other = ''

                                    if "versionStartIncluding" in cpe:
                                        versionStartIncluding = cpe["versionStartIncluding"]
                                        check = False
                                    else:
                                        versionStartIncluding = ''

                                    if "versionEndIncluding" in cpe:
                                        versionEndIncluding = cpe["versionEndIncluding"]
                                        check = False
                                    else:
                                        versionEndIncluding = ''

                                    if "versionEndExcluding" in cpe:
                                        versionEndExcluding = cpe["versionEndExcluding"]
                                        check = False
                                    else:
                                        versionEndExcluding = ''

                                    if "versionStartExcluding" in cpe:
                                        versionStartExcluding = cpe["versionStartExcluding"]
                                        check = False
                                    else:
                                        versionStartExcluding = ''

                                    if check:
                                        version = version
                                        if version != "-":
                                            patch = 'Vulnerable version %s' % version
                                        else:
                                            patch = ''
                                    else:
                                        if versionStartIncluding:
                                            if versionEndIncluding:
                                                version = "[%s:%s]" % (versionStartIncluding, versionEndIncluding)
                                                patch = "Upgrade later version of %s" % versionEndIncluding
                                            if versionEndExcluding:
                                                version = "[%s:%s)" % (versionStartIncluding, versionEndExcluding)
                                                patch = "Upgrade version %s" % versionEndExcluding
                                        elif versionStartExcluding:
                                            if versionEndIncluding:
                                                version = "(%s:%s]" % (versionStartExcluding, versionEndIncluding)
                                                patch = "Upgrade later version of %s" % versionEndIncluding
                                            if versionEndExcluding:
                                                version = "(%s:%s)" % (versionStartExcluding, versionEndExcluding)
                                                patch = "Upgrade version %s" % versionEndExcluding
                                        else:
                                            if versionEndIncluding:
                                                version = "[0.0:%s]" % versionEndIncluding
                                                patch = "Upgrade later version of %s" % versionEndIncluding
                                            if versionEndExcluding:
                                                version = "[0.0:%s)" % versionEndExcluding
                                                patch = "Upgrade version %s" % versionEndExcluding

                                    product = product.replace("'", "")
                                    vendor = vendor.replace("'", "")
                                    patch = patch.replace("'", "")
                                    version = version.replace("'", "")
                                    part = part.replace("'", "")
                                    update = update.replace("'", "")
                                    language = language.replace("'", "")


                                    affected_version = {}
                                    affected_version['product'] = product
                                    affected_version['vendor'] = vendor
                                    affected_version['patch'] = patch
                                    affected_version['version'] = version

                                    res = {}
                                    res['part'] = part
                                    
                                    type ="NVD"
                                    advisory = 'ADV'

                                    niah_adv_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())

                                    #if self.check_product_entry(niah_adv_id):
                                    if niah_adv_id not in self.product_entry:
                                        query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision, vuln_status) values('%s', '%s', '%s', '%s', '%s', '%s', '0', 'indev')" % (niah_adv_id, product, vendor, type, advisory, json.dumps(res))
                                        self.cursor.execute(query)
                                        self.connection.commit()
                                        self.product_entry[niah_adv_id] = '0'
        
                                        updated_cves['product_ids'].append(niah_adv_id)

                                        query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_adv_id, 'indev', date_update, '0')
                                        #print(query)
                                        self.cursor.execute(query)
                                        self.connection.commit()

                                    if niah_adv_id not in results[niah_version_id]:
                                        results[niah_version_id][niah_adv_id] = []

                                    if affected_version not in results[niah_version_id][niah_adv_id]:
                                        results[niah_version_id][niah_adv_id].append(affected_version)

                                    if niah_version_id not in affected_products_versions:
                                        affected_products_versions.append(niah_version_id)

                        elif 'cpe_match' in node:
                            for cpe in node['cpe_match']:
                                vulnerable = cpe['vulnerable']
                                cpe23Uri = cpe['cpe23Uri']
                                
                                if re.findall(r'cpe:2\.3:(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?)', str(cpe23Uri)):
                                    cpe_data = re.findall(r'cpe:2\.3:(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?)', str(cpe23Uri))[0]
                                    part = cpe_data[0]
                                    vendor = cpe_data[1]
                                    product = cpe_data[2]
                                    version = cpe_data[3]
                                    update = cpe_data[4]
                                    edition = cpe_data[5]
                                    language = cpe_data[6]
                                    software_edition = cpe_data[7]
                                    target_software = cpe_data[8]
                                    target_hardware = cpe_data[9]
                                    other = cpe_data[10]
                                elif re.findall(r'cpe:\/(.*?):(.*?):(.*?):(.*?):(.*)', str(cpe23Uri)):
                                    cpe_data = re.findall(r'cpe:\/(.*?):(.*?):(.*?):(.*?):(.*)', str(cpe23Uri))[0]
                                    part = cpe_data[0]
                                    vendor = cpe_data[1]
                                    product = cpe_data[2]
                                    version = cpe_data[3]
                                    update = cpe_data[4]
                                    edition = ''
                                    language = ''
                                    software_edition = ''
                                    target_software = ''
                                    target_hardware = ''
                                    other = ''

                                check = True

                                if "versionStartIncluding" in cpe:
                                    versionStartIncluding = cpe["versionStartIncluding"]
                                    check = False
                                else:
                                    versionStartIncluding = ''

                                if "versionEndIncluding" in cpe:
                                    versionEndIncluding = cpe["versionEndIncluding"]
                                    check = False
                                else:
                                    versionEndIncluding = ''

                                if "versionEndExcluding" in cpe:
                                    versionEndExcluding = cpe["versionEndExcluding"]
                                    check = False
                                else:
                                    versionEndExcluding = ''

                                if "versionStartExcluding" in cpe:
                                    versionStartExcluding = cpe["versionStartExcluding"]
                                    check = False
                                else:
                                    versionStartExcluding = ''

                                if check:
                                    version = version
                                    if version != "-":
                                        patch = 'Vulnerable version %s' % version
                                    else:
                                        patch = ''

                                else:
                                    if versionStartIncluding:
                                        if versionEndIncluding:
                                            version = "[%s:%s]" % (versionStartIncluding, versionEndIncluding)
                                            patch = "Upgrade later version of %s" % versionEndIncluding
                                        if versionEndExcluding:
                                            version = "[%s:%s)" % (versionStartIncluding, versionEndExcluding)
                                            patch = "Upgrade version %s" % versionEndExcluding
                                    elif versionStartExcluding:
                                        if versionEndIncluding:
                                            version = "(%s:%s]" % (versionStartExcluding, versionEndIncluding)
                                            patch = "Upgrade later version of %s" % versionEndIncluding
                                        if versionEndExcluding:
                                            version = "(%s:%s)" % (versionStartExcluding, versionEndExcluding)
                                            patch = "Upgrade version %s" % versionEndExcluding
                                    else:
                                        if versionEndIncluding:
                                            version = "[0.0:%s]" % versionEndIncluding
                                            patch = "Upgrade later version of %s" % versionEndIncluding
                                        if versionEndExcluding:
                                            version = "[0.0:%s)" % versionEndExcluding
                                            patch = "Upgrade version %s" % versionEndExcluding
                                
                                product = product.replace("'", "")
                                vendor = vendor.replace("'", "")
                                patch = patch.replace("'", "")
                                version = version.replace("'", "")
                                part = part.replace("'", "")
                                update = update.replace("'", "")
                                language = language.replace("'", "")


                                affected_version = {}
                                affected_version['product'] = product
                                affected_version['vendor'] = vendor
                                affected_version['patch'] = patch
                                affected_version['version'] = version

                                res = {}
                                res['part'] = part
                                    
                                type ="NVD"
                                advisory = 'ADV'

                                niah_adv_id = "NIAH-NVD-ADV-%s-%s" % (vendor.upper(), product.upper())

                                #if self.check_product_entry(niah_adv_id):
                                if niah_adv_id not in self.product_entry:
                                    query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision, vuln_status) values('%s', '%s', '%s', '%s', '%s', '%s', '0', 'indev')" % (niah_adv_id, product, vendor, type, advisory, json.dumps(res))
                                    self.cursor.execute(query)
                                    self.connection.commit()  
                                    self.product_entry[niah_adv_id] = '0'

                                    updated_cves['product_ids'].append(niah_adv_id)

                                    query = "INSERT INTO history(username, type, niahid, status, lastupdated, revision) values('%s', '%s', '%s', '%s', '%s', '%s')" % ('system@niahsecurity.io', 'product', niah_adv_id, 'indev', date_update, '0')
                                    #print(query)
                                    self.cursor.execute(query)
                                    self.connection.commit()

                                if niah_adv_id not in results[niah_version_id]:
                                    results[niah_version_id][niah_adv_id] = []

                                if affected_version not in results[niah_version_id][niah_adv_id]:
                                    results[niah_version_id][niah_adv_id].append(affected_version)
                                
                                if niah_version_id not in affected_products_versions:
                                    affected_products_versions.append(niah_version_id)

            
            check = True
        
            if niahId in self.niahid_entry:
                revision = int(self.niahid_entry[niahId]['revision']) + 1
                if lastModifiedDate == self.niahid_entry[niahId]['lastmodifieddate']:
                    check = False
                self.niahid_entry[niahId]['revision'] = int(self.niahid_entry[niahId]['revision']) + 1
                self.niahid_entry[niahId]['lastmodifieddate'] = lastModifiedDate

                fetchData = self.check_niahid_entry(niahId)
                if fetchData:
                    affected_products_versions_old = fetchData[0][7]
                    for affected_version_nu in affected_products_versions_old:
                        if affected_version_nu not in affected_products_versions:
                            affected_products_versions.append(affected_version_nu)
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
                
                updated_cves['niah_ids'].append(niahId)

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
                query = "INSERT INTO affected_versions_tab(niah_version_id, versions, revision, vuln_status) values('%s', '%s', '%s', 'indev')" % (niah_version_id, json.dumps(results[niah_version_id]), revision)
                #print(query)
                self.cursor.execute(query)
                self.connection.commit() 

                #message = "(NIAH-VULN-ID : %s) %s CVE updated" % (niahId, data_id)
                #res = check_alerts()
                #res.update_alerts('cve_id', data_id, self.date_update, message)
        
        with open(update_filename, 'w') as outfile:
            json.dump(updated_cves, outfile, indent=2)
            

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    print("Start - %s" % date_update)
    res = nvdGet(date_update)
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    print("End - %s" % date_update)
