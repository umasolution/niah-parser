from cgitb import reset
from ensurepip import version
from operator import truediv
import os
from platform import platform
import sys
import ast
import os.path
from os import path
import json
import sqlite3
from vt_adv import moniVTDB
from git_adv import git_sync
import requests
from dateConvert import dateConvert
import datetime
import time
import re
import configparser
import psycopg2
from bs4 import BeautifulSoup
import requests
import re
import json
from tqdm import tqdm

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

def mk2arg(head, x):
    import os
    return mkarg(os.path.join(head, x))

def mkarg(x):
    if '\'' not in x:
        return ' \'' + x + '\''
    s = ' "'
    for c in x:
        if c in '\\$"`':
            s = s + '\\'
        s = s + c
    s = s + '"'
    return s


class cveFeed():
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
        
        sys.setrecursionlimit(100000)

    def get_uniq(self, data):
        details = []
        for d in data:
            if d not in details:
                details.append(d)


    def getCWEText(self, cwes):
        cwes_text = []
        try:
            for cwe in cwes.split(','):
                cwe = cwe.strip()
                query = "select cwe_str from cwe_map where cwe_no='%s'" % cwe
                self.cursor.execute(query)
                fetchData = self.cursor.fetchall()

                if len(fetchData) > 0:
                    cwe_text = fetchData[0][0]
                else:
                    cwe_text = ''

                    cweno = re.sub(r'CWE-', '', str(cwe), re.IGNORECASE)
                    url = "https://cwe.mitre.org/data/definitions/%s.html" % cweno
                    page = requests.get(url)
                    soup = BeautifulSoup(page.content, "html.parser")

                    if soup.findAll('h2'):
                        cwe_text = soup.findAll('h2')[0].cwe_text

                    query = "insert into cwe_map(cwe_no, cwe_str) values('%s', '%s')" % (cwe, cwe_text)
                    self.cursor.execute(query)
                    self.connection.commit()

                cwes_text.append(cwe_text)
            
            return ','.join(cwes_text)
        except:
            return cwes

    def get_versions_details(self, affected_products_versions):
        versions_completed = []
        
        results = []

        for niah_version_id in affected_products_versions:
            if niah_version_id not in versions_completed:
                versions_completed.append(niah_version_id)
                cmd = "select versions from affected_versions_tab where niah_version_id='%s' ORDER BY revision DESC limit 1" % niah_version_id
                self.cursor.execute(cmd)
                fetchData = self.cursor.fetchall()
                if len(fetchData) > 0:
                    versions_details = fetchData[0][0]
                    product_completed = []
                    for niah_product_id in versions_details:
                        if niah_product_id not in product_completed:
                            product_completed.append(niah_product_id)
                            product_data = self.get_product_details(niah_product_id)

                            res = {}
                            res['niah_product_id'] = niah_product_id   
                            res['niah_version_id'] = niah_version_id 
                            res['type'] = product_data['type']
                            res['advisory'] = product_data['advisory']
                            res['product'] = product_data['product']
                            res['vendor'] = product_data['vendor']
                            for k, v in product_data['data'].items():
                                res[k] = v
                            res['affectedversions'] = []
                            for detail in versions_details[niah_product_id]:
                                version = ''
                                patch = ''

                                r = {}
                                if 'patch' in detail:
                                    patch = detail['patch']
                                
                                if 'version' in detail:
                                    version = detail['version']
                               
                                if 'versions' in detail:
                                    version = detail['versions']
                                
                                if 'platform' in detail:
                                    platform = detail['platform']
                                    r['platform'] = platform
                                
                                if 'advisoryid' in detail:
                                    advisoryid = detail['advisoryid']
                                    r['advisoryid'] = advisoryid

                                if not version:
                                    r['patch'] = "-"
                                else:
                                    r['patch'] = patch

                                r['version'] = version

                                if r not in res['affectedversions']:
                                    res['affectedversions'].append(r)

                            
                            results.append(res)
        
        return results

    def get_product_details(self, niah_product_id):
        cmd = "select product, vendor, advisory, type, data from product_reference_tab where niah_product_id='%s' ORDER BY revision DESC limit 1" % niah_product_id
        self.cursor.execute(cmd)
        fetchData = self.cursor.fetchall()
        
        if len(fetchData) > 0:
            product = fetchData[0][0]
            vendor = fetchData[0][1]
            advisory = fetchData[0][2]
            type = fetchData[0][3]
            data = fetchData[0][4]

            res = {}
            res['product'] = product
            res['vendor'] = vendor
            res['advisory'] = advisory
            res['type'] = type
            res['data'] = data

            return res
        else:
            return False

    def fix_product_details(self):
        products_data= []
        cmd = "select niah_product_id, product, vendor, advisory, type, data, revision from product_reference_tab ORDER BY revision DESC"
        self.cursor.execute(cmd)
        fetchData = self.cursor.fetchall()
        
        for row in tqdm(fetchData):
            niah_product_id = row[0]
            if niah_product_id not in products_data:
                products_data.append(niah_product_id)
                product = row[1]
                vendor = row[2]
                advisory = row[3]
                type = row[4]
                data = row[5]
                revision = row[6] + 1
                
                check = False

                for k, v in data.items():
                    if k == "language":
                        if v == "en" or v == "data\\" or v == "netmask":
                            del data['language']
                            check = True
                            break
                        elif v == "Composer":
                            data['language'] = "php"
                            check = True
                            break
                        elif v == "Go":
                            data['language'] = "golang"
                            check = True
                            break
                        elif v == "Maven":
                            data['language'] = "java"
                            check = True
                            break
                        elif v == "NuGet":
                            data['language'] = "nuget"
                            check = True
                            break
                        elif v == "RubyGems":
                            data['language'] = "ruby"
                            check = True
                            break
                        elif v == "Rust":
                            data['language'] = "rust"
                            check = True
                            break

                if check:
                    query = "INSERT INTO product_reference_tab(niah_product_id, product, vendor, type, advisory, data, revision) values('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (niah_product_id, product, vendor, type, advisory, json.dumps(data), revision)
                    self.cursor.execute(query)
                    self.connection.commit()

        print("done")

    def get_exploits(self, year_number):
        query = "select reference, application, cve_id from pocreference_db where cve_id LIKE '%%CVE-%s-%%'" % year_number
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall();

        print("[ OK ] PoC Table Sync started")

        retRes = {}

        if len(fetchData) > 0:
            for data in tqdm(fetchData):
                reference = data[0]
                application = data[1]
                cve_id = data[2]

                if cve_id not in retRes:
                    retRes[cve_id] = []

                res = {}
                res['Advisory'] = application 
                res['Reference'] = reference

                if res not in retRes[cve_id]:
                    retRes[cve_id].append(res)

        return retRes

    def nvdLoad(self, date_update): 
        with open("application.config", "r") as f:
            app_json_db = json.load(f)

        applications = []

        for app in app_json_db['packageRegex']:
            applications.append(app)

        applications_lists = {}
        applications_lists['publishDate'] = date_update
        applications_lists['data'] = []

        platform_lists = {}
        platform_lists['publishDate'] = date_update
        platform_lists['data'] = {}
        platform_lists['metadata'] = {}

        year_number = datetime.datetime.now().year
        
        year_tab = []

        while year_number >= 2001:
            year_tab.append(year_number)
            year_number -= 1
            
        year_tab.append('0000')
        
        res_tables = []

        results = {}
        results['language'] = {}
        results['plugin'] = {}
        results['platform'] = {}

        i = 0

        for year_number in year_tab:
            exploits_db = self.get_exploits(year_number)

            complete_res = []
            
            retRes = {}
            vulns = []
                        
            print("[ OK ] vuln Table Sync started")
            if year_number == '0000':
                cmd = "select distinct(niahid), data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision from vuln_tab where data_id not LIKE '%%CVE-%%' ORDER BY revision DESC"
            else:
                cmd = "select distinct(niahid), data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision from vuln_tab where data_id LIKE '%%CVE-%s-%%' ORDER BY revision DESC" % year_number

            self.cursor.execute(cmd)
            fetchData = self.cursor.fetchall()
            for row in tqdm(fetchData):
                niahid = row[0]
                if niahid not in complete_res:
                    complete_res.append(niahid)
                    data_type = row[1]
                    data_id = row[2]
                    data_id = data_id.upper()
                    cve_id = data_id
                    if niahid not in vulns:
                        vulns.append(niahid)
                        cwe_data = row[3]
                        reference_data = row[4]
                        try:
                            if 'data' not in reference_data:
                                reference_data['data'] = []
                        except:
                            reference_data = {}
                            reference_data['data'] = []

                        description = row[5]
                        basemetricv3_data = row[6]
                        basemetricv2_data = row[7]
                        publisheddate = row[8]
                        lastmodifieddate = row[9]
                        affected_products_versions = row[10]
                        status = row[11]
                        vuln_status = row[12]
                        revision = row[13]
                        
                        if cve_id not in retRes:
                            retRes[cve_id] = {}
                            retRes[cve_id]['niahid'] = niahid
                            retRes[cve_id]['data_type'] = data_type
                            retRes[cve_id]['data_id'] = data_id
                            retRes[cve_id]['cve_id'] = cve_id
                            retRes[cve_id]['data_type'] = data_type
                            retRes[cve_id]['data_id'] = data_id
                            retRes[cve_id]['CVE ID'] = cve_id
                            retRes[cve_id]['Products'] = {}
                            retRes[cve_id]['Products']['data'] = []

                            retRes[cve_id]['publishedDate'] = publisheddate
                            retRes[cve_id]['lastModifiedDate'] = lastmodifieddate

                        if 'data' in cwe_data:
                            retRes[cve_id]['CWE'] = ','.join(self.uniq_cwe(cwe_data['data']))
                        else:
                            retRes[cve_id]['CWE'] = ''
                        if 'nvd' in description:
                            retRes[cve_id]['description'] = description['nvd']
                        else:
                            retRes[cve_id]['description'] = ''
                        
                        retRes[cve_id]['CVSS30'] = {}
                        if 'attackVector' in basemetricv3_data:
                            retRes[cve_id]['CVSS30']['attackVector'] = basemetricv3_data['attackVector'].upper()
                        else:
                            retRes[cve_id]['CVSS30']['attackVector'] = ''
                        if 'vectorString' in basemetricv3_data:
                            retRes[cve_id]['CVSS30']['vectorString'] = basemetricv3_data['vectorString']
                        else:
                            retRes[cve_id]['CVSS30']['vectorString'] = ''
                        if 'exploitabilityScore' in basemetricv3_data:
                            retRes[cve_id]['CVSS30']['exploitabilityScore'] = basemetricv3_data['exploitabilityScore']
                        else:
                            retRes[cve_id]['CVSS30']['exploitabilityScore'] = ''
                        if 'baseScore' in basemetricv3_data:
                            retRes[cve_id]['CVSS30']['baseScore'] = basemetricv3_data['baseScore']
                        else:
                            retRes[cve_id]['CVSS30']['baseScore'] = ''
                        if 'baseSeverity' in basemetricv3_data:
                            retRes[cve_id]['CVSS30']['baseSeverity'] = basemetricv3_data['baseSeverity'].upper()
                        else:
                            retRes[cve_id]['CVSS30']['baseSeverity'] = ''

                        retRes[cve_id]['Reference'] = ','.join(reference_data['data'])

                        retRes[cve_id]['CVSS20'] = {}
                        if 'accessVector' in basemetricv2_data:
                            retRes[cve_id]['CVSS20']['attackVector'] = basemetricv2_data['accessVector'].upper()
                        else:
                            retRes[cve_id]['CVSS20']['attackVector'] = ''
                        if 'vectorString' in basemetricv2_data:
                            retRes[cve_id]['CVSS20']['vectorString'] = basemetricv2_data['vectorString']
                        else:
                            retRes[cve_id]['CVSS20']['vectorString'] = ''
                        if 'exploitabilityScore' in basemetricv2_data:
                            retRes[cve_id]['CVSS20']['exploitabilityScore'] = basemetricv2_data['exploitabilityScore']
                        else:
                            retRes[cve_id]['CVSS20']['exploitabilityScore'] = ''
                        if 'baseScore' in basemetricv2_data:
                            retRes[cve_id]['CVSS20']['baseScore'] = basemetricv2_data['baseScore']
                        else:
                            retRes[cve_id]['CVSS20']['baseScore'] = ''
                        if 'severity' in basemetricv2_data:
                            retRes[cve_id]['CVSS20']['baseSeverity'] = basemetricv2_data['severity'].upper()
                        else:
                            retRes[cve_id]['CVSS20']['baseSeverity'] = ''

                        if cve_id in exploits_db:
                            retRes[cve_id]['Exploits'] = exploits_db[cve_id]
                        else:
                            retRes[cve_id]['Exploits'] = []

                        details = self.get_versions_details(affected_products_versions)
                        
                        for detail in details:
                            niah_product_id = detail['niah_product_id']
                            niah_version_id = detail['niah_version_id']
                            product = detail['product']
                            if 'vendor' in detail:
                                vendor = detail['vendor']
                            else:
                                vendor = ''
                            appVendor = ''
                            if 'part' in detail:
                                part = detail['part']
                            else:
                                part = ''
                            if 'advisory' in detail:
                                advisory = detail['advisory']
                            else:
                                advisory = ''
                            if 'type' in detail:
                                type = detail['type']
                            else:
                                type = ''
                            
                            groupid = ''
                            artifactid = ''
                            packagename = ''

                            if 'groupid' in detail:
                                groupid = detail['groupid']
                            if 'artifactid' in detail:
                                artifactid = detail['artifactid']
                            if 'packagename' in detail:
                                packagename = detail['packagename']

                            for det in detail['affectedversions']:
                                version = det['version']
                                patch = det['patch']

                                res = {}
                                res['product'] = product
                                if groupid:
                                    res['groupid'] = groupid
                                if artifactid:
                                    res['artifactid'] = artifactid
                                if packagename:
                                    res['packagename'] = packagename
                                res['product'] = product
                                res['vendor'] = vendor   
                                res['version'] = version
                                res['patch'] = patch
                                res['type'] = part
                                res['appVendor'] = appVendor
                                res['niah_version_id'] = niah_version_id
                                res['niah_product_id'] = niah_product_id

                                if 'language' in detail:
                                    if 'library_advisory' not in retRes[cve_id]:
                                        retRes[cve_id]['library_advisory'] = {}
                                        retRes[cve_id]['library_advisory']['title'] = "Library Advisory"
                                        retRes[cve_id]['library_advisory']['data'] = []

                                    res['language'] = detail['language']

                                    retRes[cve_id]['library_advisory']['data'].append(res)

                                    if detail['language'] not in results['language']:
                                        results['language'][detail['language']] = {}
                                    if cve_id not in results['language'][detail['language']]:
                                        results['language'][detail['language']][cve_id] = []
                                    if res not in results['language'][detail['language']][cve_id]:
                                        results['language'][detail['language']][cve_id].append(res)

                                if 'plugin' in detail:
                                    if 'plugin_advisory' not in retRes[cve_id]:
                                        retRes[cve_id]['plugin_advisory'] = {}
                                        retRes[cve_id]['plugin_advisory']['title'] = "Plugin Advisory"
                                        retRes[cve_id]['plugin_advisory']['data'] = []

                                    res['plugin'] = detail['plugin']

                                    retRes[cve_id]['plugin_advisory']['data'].append(res)

                                    if detail['plugin'] not in results['plugin']:
                                        results['plugin'][detail['plugin']] = {}
                                    if cve_id not in results['plugin'][detail['plugin']]:
                                        results['plugin'][detail['plugin']][cve_id] = []

                                    if res not in results['plugin'][detail['plugin']][cve_id]:
                                        results['plugin'][detail['plugin']][cve_id].append(res)

                                if type == "platform":
                                    if 'platform_advisory' not in retRes[cve_id]:
                                        retRes[cve_id]['platform_advisory'] = {}
                                        retRes[cve_id]['platform_advisory']['title'] = "Platform Advisory"
                                        retRes[cve_id]['platform_advisory']['data'] = []

                                    if 'advisoryid' in det:
                                        res['advisoryid'] = det['advisoryid']
                                    else:
                                        res['advisoryid'] = ''

                                    res['platform'] = det['platform']

                                    if advisory not in platform_lists['data']:
                                        platform_lists['data'][advisory] = {}

                                    if det['platform'] not in platform_lists['data'][advisory]:
                                        platform_lists['data'][advisory][det['platform']] = []

                                    res_platform = {}
                                    res_platform = res
                                    res_platform['baseScoreV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseScore'])
                                    res_platform['severityV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseSeverity'])
                                    res_platform['accessvectorV2'] ="%s" % (retRes[cve_id]['CVSS20']['attackVector'])
                                    res_platform['baseScoreV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseScore'])
                                    res_platform['severityV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseSeverity'])
                                    res_platform['accessvectorV3'] ="%s" % (retRes[cve_id]['CVSS30']['attackVector'])
                                    res_platform['baseScore'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseScore'], retRes[cve_id]['CVSS30']['baseScore'])
                                    res_platform['severity'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseSeverity'], retRes[cve_id]['CVSS30']['baseSeverity'])
                                    res_platform['accessvector'] ="%s/%s" % (retRes[cve_id]['CVSS20']['attackVector'], retRes[cve_id]['CVSS30']['attackVector'])
                                    res_platform['vectorStringV2'] = retRes[cve_id]['CVSS20']['vectorString']
                                    res_platform['vectorStringV3'] = retRes[cve_id]['CVSS30']['vectorString']
                                    res_platform['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
                                    res_platform['publishedDate'] = retRes[cve_id]['publishedDate'] 
                                    res_platform['niahid'] = retRes[cve_id]['niahid']
                                    res_platform['reference'] = retRes[cve_id]['Reference']
                                    res_platform['description'] = retRes[cve_id]['description']
                                    res_platform['cwe'] = self.getCWEText(retRes[cve_id]['CWE'])
                                    res_platform['data_id'] = data_id
                                    res_platform['cve_id'] = cve_id

                                    if advisory == "ubuntu":
                                        reference = "https://ubuntu.com/security/%s" % cve_id.upper()
                                        res['family'] = "ubuntu"
                                        res['vendor'] = "ubuntu"
                                        res_platform['family'] = "ubuntu"
                                        res_platform['vendor'] = "ubuntu"
                                        
                                        if reference not in reference_data['data']:
                                            reference_data['data'].append(reference)
                                        
                                        retRes[cve_id]['platform_advisory']['data'].append(res)
                                        
                                        #if 'ubuntu' not in results['platform']:
                                        #    results['platform']['ubuntu'] = {}
                                        
                                        #if cve_id not in results['platform']['ubuntu']:
                                        #    results['platform']['ubuntu'][cve_id] = []
                                        
                                        #if res not in results['platform']['ubuntu'][cve_id]:
                                        #    results['platform']['ubuntu'][cve_id].append(res)
                                        
                                        if 'Exploits' in retRes[cve_id]:
                                            res_platform['exploits'] = self.get_exploit_str(retRes[cve_id]['Exploits'])
                                        else:
                                            res_platform['exploits'] = ''

                                        if res_platform not in platform_lists['data'][advisory][det['platform']]: 
                                            platform_lists['data'][advisory][det['platform']].append(res_platform)

                                    if advisory == "debian":
                                        reference = "https://security-tracker.debian.org/tracker/%s" % cve_id.upper()
                                        res['family'] = "debian"
                                        res['vendor'] = "debian"
                                        res_platform['family'] = "debian"
                                        res_platform['vendor'] = "debian"

                                        if reference not in reference_data['data']:
                                            reference_data['data'].append(reference)
                                        retRes[cve_id]['platform_advisory']['data'].append(res)

                                        #if 'debian' not in results['platform']:
                                        #    results['platform']['debian'] = {}
                                        #if cve_id not in results['platform']['debian']:
                                        #    results['platform']['debian'][cve_id] = []
                                        #if res not in results['platform']['debian'][cve_id]:
                                        #    results['platform']['debian'][cve_id].append(res)

                                        if res_platform not in platform_lists['data'][advisory][det['platform']]: 
                                            platform_lists['data'][advisory][det['platform']].append(res_platform)

                                if advisory == "ADV":
                                    if res not in retRes[cve_id]['Products']['data']:
                                        retRes[cve_id]['Products']['data'].append(res)


                                if product in applications:
                                    res['baseScoreV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseScore'])
                                    res['severityV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseSeverity'])
                                    res['accessvectorV2'] = "%s" % (retRes[cve_id]['CVSS20']['attackVector'])
                                    res['baseScoreV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseScore'])
                                    res['severityV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseSeverity'])
                                    res['accessvectorV3'] = "%s" % (retRes[cve_id]['CVSS30']['attackVector'])
                                    if retRes[cve_id]['CVSS30']['baseScore']:
                                        res['baseScore'] = retRes[cve_id]['CVSS30']['baseScore']
                                    else:
                                        res['baseScore'] = retRes[cve_id]['CVSS20']['baseScore']
                                    if retRes[cve_id]['CVSS30']['baseSeverity']:
                                        res['severity'] = retRes[cve_id]['CVSS30']['baseSeverity']
                                    else:
                                        res['severity'] = retRes[cve_id]['CVSS20']['baseSeverity']
                                    if retRes[cve_id]['CVSS30']['attackVector']:
                                        res['accessvector'] = retRes[cve_id]['CVSS30']['attackVector']
                                    else:
                                        res['accessvector'] = retRes[cve_id]['CVSS20']['attackVector']
                                    res['vectorStringV2'] = retRes[cve_id]['CVSS20']['vectorString']
                                    res['vectorStringV3'] = retRes[cve_id]['CVSS30']['vectorString']
                                    if retRes[cve_id]['CVSS30']['vectorString']:
                                        res['vectorString'] = retRes[cve_id]['CVSS30']['vectorString']
                                    else:
                                        res['vectorString'] = retRes[cve_id]['CVSS20']['vectorString']
                                    res['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
                                    res['publishedDate'] = retRes[cve_id]['publishedDate'] 
                                    res['niahid'] = retRes[cve_id]['niahid']
                                    res['reference'] = retRes[cve_id]['Reference']
                                    res['description'] = retRes[cve_id]['description']
                                    res['cwe'] = self.getCWEText(retRes[cve_id]['CWE'])
                                    res['data_id'] = data_id
                                    res['cve_id'] = cve_id

                                    if res not in applications_lists['data']:
                                        applications_lists['data'].append(res)

            complete_res = []

            print("[ OK ] CVEs feed generation started")
            res_db = {}
            fetchData = ''
            
            for cve_id in retRes:
                with open("/var/DB/CVEs/%s.json" % (cve_id), "w") as outfile:
                    json.dump(retRes[cve_id], outfile, indent = 2)

                data_type = retRes[cve_id]['data_type']
                data_id = retRes[cve_id]['data_id']
                publishedDate = retRes[cve_id]['publishedDate']

                if data_type == "CVE":
                    year = data_id.split("-")[1]
                else:
                    year = publishedDate.split("-")[0]

                if year not in res_db:
                    res_db[year] = {}

                if cve_id not in res_db[year]:
                    res_db[year][cve_id] = {}

                res_tab = {}
                res_tab['year'] = year
                res_tab['vulnerability'] = cve_id
                res_tab['cve_id'] = cve_id
                res_tab['niahid'] = retRes[cve_id]['niahid']
                res_tab['cwe'] = retRes[cve_id]['CWE'] 
                res_tab['products'] = []
                res_tab['vendors'] = []
                res_tab['family'] = []
                res_tab['language'] = []
                res_tab['plugin'] = []
                res_tab['part'] = []
                res_tab['platform'] = []
                res_tab['advisoryid'] = []
                  
                for pkg in retRes[cve_id]['Products']['data']:
                    if pkg['product'] not in res_tab['products']:
                        if pkg['product'] not in res_tab['products']:
                            res_tab['products'].append(pkg['product'])
                    if pkg['vendor'] not in  res_tab['vendors']:
                        if pkg['vendor'] not in res_tab['vendors']:
                            res_tab['vendors'].append(pkg['vendor'])
                    if 'type' in pkg:
                        if pkg['type'] not in res_tab['part']:
                            res_tab['part'].append(pkg['type'])

                if 'platform_advisory' in retRes[cve_id]:
                    for pkg in retRes[cve_id]['platform_advisory']['data']:
                        if 'family' in pkg:
                            if pkg['family'] not in res_tab['family']:
                                res_tab['family'].append(pkg['family'])
                        if 'platform' in pkg:
                            if pkg['platform'] not in res_tab['platform']:
                                res_tab['platform'].append(pkg['platform'])
                        if 'advisoryid' in pkg:
                            if pkg['advisoryid'] not in res_tab['advisoryid']:
                                res_tab['advisoryid'].append(pkg['advisoryid'])
                    

                if 'plugin_advisory' in retRes[cve_id]:
                    for pkg in retRes[cve_id]['plugin_advisory']['data']:
                        if 'plugin' in pkg:
                            if pkg['plugin'] not in res_tab['plugin']:
                                res_tab['plugin'].append(pkg['plugin'])

                if 'library_advisory' in retRes[cve_id]:
                    for pkg in retRes[cve_id]['library_advisory']['data']:
                        if 'language' in pkg:
                            if pkg['language'] not in res_tab['language']:
                                res_tab['language'].append(pkg['language'])

                res_db[year][cve_id]['products'] = retRes[cve_id]['Products']['data']
                res_db[year][cve_id]['niahid'] = retRes[cve_id]['niahid']
                res_db[year][cve_id]['cve_id'] = cve_id        
                res_db[year][cve_id]['vuln_name'] = cve_id            
                res_db[year][cve_id]['reference'] = retRes[cve_id]['Reference']                    
                res_db[year][cve_id]['cwe_str'] = self.getCWEText(retRes[cve_id]['CWE'])                   
                res_db[year][cve_id]['publishedDate'] = retRes[cve_id]['publishedDate']                   
                res_db[year][cve_id]['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']                   
                res_db[year][cve_id]['description'] = retRes[cve_id]['description']                  
                if 'Exploits' in retRes[cve_id]:
                    res_db[year][cve_id]['exploits'] = self.get_exploit_str(retRes[cve_id]['Exploits'])
                else:
                    res_db[year][cve_id]['exploits'] = ''                         
                res_db[year][cve_id]['cwe_text'] = retRes[cve_id]['CWE']                   
                res_db[year][cve_id]['baseseverity2'] = retRes[cve_id]['CVSS20']['baseSeverity']                    
                res_db[year][cve_id]['attackvector2'] = retRes[cve_id]['CVSS20']['attackVector']                    
                res_db[year][cve_id]['vectorstring2'] = retRes[cve_id]['CVSS20']['vectorString']                    
                res_db[year][cve_id]['basescore2'] = retRes[cve_id]['CVSS20']['baseScore']                    
                res_db[year][cve_id]['exploitabilityScore'] = retRes[cve_id]['CVSS20']['exploitabilityScore']                    
                res_db[year][cve_id]['baseseverity3'] = retRes[cve_id]['CVSS30']['baseSeverity']                    
                res_db[year][cve_id]['attackvector3'] = retRes[cve_id]['CVSS30']['attackVector']                    
                res_db[year][cve_id]['vectorstring3'] = retRes[cve_id]['CVSS30']['vectorString']                    
                res_db[year][cve_id]['basescore3'] = retRes[cve_id]['CVSS30']['baseScore']                    
                res_db[year][cve_id]['exploitabilityScore3'] = retRes[cve_id]['CVSS30']['exploitabilityScore']                 
                if retRes[cve_id]['CVSS30']['attackVector']:
                    res_db[year][cve_id]['attackvector'] = retRes[cve_id]['CVSS30']['attackVector']
                else:
                    res_db[year][cve_id]['attackvector'] = retRes[cve_id]['CVSS20']['attackVector']
                if retRes[cve_id]['CVSS30']['baseSeverity']:
                    res_db[year][cve_id]['baseseverity'] = retRes[cve_id]['CVSS30']['baseSeverity']
                else:
                    res_db[year][cve_id]['baseseverity'] = retRes[cve_id]['CVSS20']['baseSeverity']
                if retRes[cve_id]['CVSS30']['vectorString']:
                    res_db[year][cve_id]['vectorstring'] = retRes[cve_id]['CVSS30']['vectorString']
                else:
                    res_db[year][cve_id]['vectorstring'] = retRes[cve_id]['CVSS20']['vectorString']
                if retRes[cve_id]['CVSS30']['baseScore']:
                    res_db[year][cve_id]['basescore'] = retRes[cve_id]['CVSS30']['baseScore']
                else:
                    res_db[year][cve_id]['basescore'] = retRes[cve_id]['CVSS20']['baseScore']

                res_tab['baseScoreV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseScore'])
                res_tab['severityV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseSeverity'])
                res_tab['accessvectorV2'] ="%s" % (retRes[cve_id]['CVSS20']['attackVector'])
                res_tab['baseScoreV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseScore'])
                res_tab['severityV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseSeverity'])
                res_tab['accessvectorV3'] ="%s" % (retRes[cve_id]['CVSS30']['attackVector'])
                res_tab['baseScore'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseScore'], retRes[cve_id]['CVSS30']['baseScore'])
                res_tab['severity'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseSeverity'], retRes[cve_id]['CVSS30']['baseSeverity'])
                res_tab['accessvector'] ="%s/%s" % (retRes[cve_id]['CVSS20']['attackVector'], retRes[cve_id]['CVSS30']['attackVector'])
                res_tab['vectorStringV3'] = retRes[cve_id]['CVSS30']['vectorString']
                res_tab['vectorStringV2'] = retRes[cve_id]['CVSS20']['vectorString']
                if res_tab['vectorStringV3']:
                    res_tab['vectorString'] = retRes[cve_id]['CVSS30']['vectorString']
                else:
                    res_tab['vectorString'] = retRes[cve_id]['CVSS20']['vectorString']

                res_tab['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
                res_tables.append(res_tab)


            # Vulnerability DB Generated (Year Wise)
            for year in res_db:
                with open("/var/DB/feeds/nvd/%s_db.json" % year, "w") as f:
                    json.dump(res_db[year], f, indent = 2)  

                r_results = []
                for cve_id in res_db[year]:
                    r_data = res_db[year][cve_id]
                    r_results.append(r_data)

                with open("/var/DB/feeds/nvd/%s.json" % year, "w") as f:
                    json.dump(r_results, f, indent = 2)

        # Table View data
        with open("/var/DB/feeds/nvd/vuln_feed.json", "w") as f:
            json.dump(res_tables, f, indent = 2)
        
        res_tables = []
        r_results = []

        # platform feeds
        print("[ OK ] Platform feed generation")
        publishDate = platform_lists['publishDate']
        for family in platform_lists['data']:
            for platform in platform_lists['data'][family]:
                res = {}
                res['publishDate'] = publishDate
                res['data'] = platform_lists['data'][family][platform]

                with open("/var/DB/feeds/platform/%s_%s.json" % (family, platform), "w") as f:
                    json.dump(res, f, indent = 2)

            with open("/var/DB/feeds/platform/%s.json" % (family), "w") as f:
                    json.dump(res, f, indent = 2)


        # Application feeds
        print("[ OK ] Application Feeds generation")
        with open("/var/DB/feeds/application/application.json", "w") as outfile:
            json.dump(applications_lists, outfile, indent = 2)


        # Language and plugin feeds
        print("[ OK ] languages, plugins and platform feeds generation started")
        for app_type in results:
            if app_type == "plugin" or app_type == "language":
                app_type_lists = {}
                app_type_lists['publishDate'] = date_update
                app_type_lists['data'] = []

                for application in results[app_type]:
                    res_data = {}
                    res_data['publishDate'] = date_update
                    res_data['data'] = []

                    for cve_id in results[app_type][application]:   
                        with open("/var/DB/CVEs/%s.json" % cve_id, "r") as f:
                            retRes[cve_id] = json.load(f)
                        for appdata in tqdm(results[app_type][application][cve_id]):
                            res = appdata
                            res['cve_id'] = cve_id
                            res['vuln_name'] = cve_id
                            res['cwe_text'] = retRes[cve_id]['CWE']
                            res['baseScoreV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseScore'])
                            res['severityV2'] = "%s" % (retRes[cve_id]['CVSS20']['baseSeverity'])
                            res['accessvectorV2'] ="%s" % (retRes[cve_id]['CVSS20']['attackVector'])
                            res['baseScoreV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseScore'])
                            res['severityV3'] = "%s" % (retRes[cve_id]['CVSS30']['baseSeverity'])
                            res['accessvectorV3'] ="%s" % (retRes[cve_id]['CVSS30']['attackVector'])
                            res['baseScore'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseScore'], retRes[cve_id]['CVSS30']['baseScore'])
                            res['severity'] = "%s/%s" % (retRes[cve_id]['CVSS20']['baseSeverity'], retRes[cve_id]['CVSS30']['baseSeverity'])
                            res['accessvector'] ="%s/%s" % (retRes[cve_id]['CVSS20']['attackVector'], retRes[cve_id]['CVSS30']['attackVector'])
                            res['vectorStringV3'] = retRes[cve_id]['CVSS30']['vectorString']
                            res['vectorStringV2'] = retRes[cve_id]['CVSS20']['vectorString']
                            if res['vectorStringV3']:
                                res['vectorString'] = retRes[cve_id]['CVSS30']['vectorString']
                            else:
                                res['vectorString'] = retRes[cve_id]['CVSS20']['vectorString']
                            res['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
                            res['publishedDate'] = retRes[cve_id]['publishedDate'] 
                            res['niahid'] = retRes[cve_id]['niahid']
                            res['reference'] = retRes[cve_id]['Reference']
                            res['description'] = retRes[cve_id]['description']
                            res['cwe'] = self.getCWEText(retRes[cve_id]['CWE'])

                            if 'Exploits' in retRes[cve_id]:
                                res['exploits'] = self.get_exploit_str(retRes[cve_id]['Exploits'])
                            else:
                                res['exploits'] = ''

                            if res not in res_data['data']: 
                                res_data['data'].append(res)

                            if res not in app_type_lists['data']:
                                app_type_lists['data'].append(res)

                    with open("/var/DB/feeds/%s/%s.json" % (app_type, application), "w") as f:
                        json.dump(res_data, f, indent = 2)
                    
                with open("/var/DB/feeds/%s/%s.json" % (app_type, app_type), "w") as f:
                    json.dump(app_type_lists, f, indent = 2)

    def uniq_cwe(self, cwe_ids):
        cwes = []
        for cwe in cwe_ids:
            if cwe not in cwes:
                cwes.append(cwe)
    
        return cwes

    def get_exploit_str(self, retRes):
        results = []
        if len(retRes) > 0:
            for ret in retRes:
                advisory = ret['Advisory']
                reference = ret['Reference']

                res = "%s : %s" % (advisory, reference)
                results.append(res)
        
            return ','.join(results)
        else:
            results = ''
            return results

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = cveFeed()
    res.nvdLoad(date_update)
    #res.fix_product_details()
