from cgitb import reset
from ensurepip import version
import os
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

    def getCWEText(self, cwe):
        query = "select cwe_str from cwe_map where cwe_no='%s'" % cwe
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            return fetchData[0][0]
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

            return cwe_text

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
                            res['type'] = product_data['type']
                            res['advisory'] = product_data['advisory']
                            res['product'] = product_data['product']
                            res['vendor'] = product_data['vendor']
                            for k, v in product_data['data'].items():
                                res[k] = v
                            res['affectedversions'] = []
                            for detail in versions_details[niah_product_id]:
                                if 'patch' in detail:
                                    patch = detail['patch']
                                else:
                                    patch = ''
                                if 'version' in detail:
                                    version = detail['version']
                                else:
                                    version = ''
                                r = {}
                                r['patch'] = patch
                                r['version'] = version
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
                    print(query)
                    self.cursor.execute(query)
                    self.connection.commit()

        print("done")


    def nvdLoad(self, date_update):
        complete_res = []
        
        retRes = {}
        vulns = []

        results = {}
        results['language'] = {}
        results['plugin'] = {}

        
        print("[ OK ] vuln Table Sync started")
        cmd = "select distinct(niahid), data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision from vuln_tab where data_id LIKE '%%CVE-2021-%%' ORDER BY revision DESC"
        self.cursor.execute(cmd)

        for row in tqdm(self.cursor.fetchall()):
            niahid = row[0]
            if niahid not in complete_res:
                complete_res.append(niahid)
                data_type = row[1]
                data_id = row[2]
                cve_id = data_id
                if niahid not in vulns:
                    vulns.append(niahid)
                    cwe_data = row[3]
                    reference_data = row[4]
                    description = row[5]
                    basemetricv3_data = row[6]
                    basemetricv2_data = row[7]
                    publisheddate = row[8]
                    lastmodifieddate = row[9]
                    affected_products_versions = row[10]
                    status = row[11]
                    vuln_status = row[12]
                    revision = row[13]

                    details = self.get_versions_details(affected_products_versions)
                    if cve_id not in retRes:
                        retRes[cve_id] = {}
                        retRes[cve_id]['CVE ID'] = cve_id
                        retRes[cve_id]['Products'] = {}
                        retRes[cve_id]['Products']['data'] = []

                    retRes[cve_id]['publishedDate'] = publisheddate
                    retRes[cve_id]['lastModifiedDate'] = lastmodifieddate

                    for detail in details:
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

                        if 'language' in detail:
                            if 'library_advisory' not in retRes[cve_id]:
                                retRes[cve_id]['library_advisory'] = {}
                                retRes[cve_id]['library_advisory']['title'] = "Library Advisory"
                                retRes[cve_id]['library_advisory']['data'] = []
                            

                        if 'plugin' in detail:
                            if 'plugin_advisory' not in retRes[cve_id]:
                                retRes[cve_id]['plugin_advisory'] = {}
                                retRes[cve_id]['plugin_advisory']['title'] = "Plugin Advisory"
                                retRes[cve_id]['plugin_advisory']['data'] = []

                        if type == "platform":
                            if 'platform_advisory' not in retRes[cve_id]:
                                retRes[cve_id]['platform_advisory'] = {}
                                retRes[cve_id]['platform_advisory']['title'] = "Platform Advisory"
                                retRes[cve_id]['platform_advisory']['data'] = []


                        for det in detail['affectedversions']:
                            version = det['version']
                            patch = det['patch']

                            res = {}
                            res['product'] = product
                            res['vendor'] = vendor   
                            res['version'] = version
                            res['patch'] = patch
                            res['type'] = part
                            res['appVendor'] = appVendor
                            retRes[cve_id]['Products']['data'].append(res)

                            if 'language' in detail:
                                res['application'] = detail['language']
                                retRes[cve_id]['library_advisory']['data'].append(res)

                                if detail['language'] not in results['language']:
                                    results['language'][detail['language']] = {}
                                if cve_id not in results['language'][detail['language']]:
                                    results['language'][detail['language']][cve_id] = res
                            
                            if 'plugin' in detail:
                                res['application'] = detail['plugin']
                                retRes[cve_id]['plugin_advisory']['data'].append(res)

                                if detail['plugin'] not in results['plugin']:
                                    results['plugin'][detail['plugin']] = {}
                                if cve_id not in results['plugin'][detail['plugin']]:
                                    results['plugin'][detail['plugin']][cve_id] = res

                            if type == "platform":
                                if advisory == "ubuntu":
                                    reference = "https://ubuntu.com/security/%s" % cve_id.upper()
                                    res = {}
                                    res['Platform'] = "Ubuntu"
                                    res['Reference'] = reference
                                    retRes[cve_id]['platform_advisory']['data'].append(res)

                                if advisory == "debian":
                                    reference = "https://security-tracker.debian.org/tracker/%s" % cve_id.upper()
                                    res = {}
                                    res['Platform'] = "Debian"
                                    res['Reference'] = reference
                                    retRes[cve_id]['platform_advisory']['data'].append(res)

                    if 'data' in cwe_data:
                        retRes[cve_id]['CWE'] = ','.join(cwe_data['data'])
                    else:
                        retRes[cve_id]['CWE'] = ''
                    if 'nvd' in description:
                        retRes[cve_id]['description'] = description['nvd']
                    else:
                        retRes[cve_id]['description'] = ''
                    
                    retRes[cve_id]['CVSS30'] = {}
                    if 'attackVector' in basemetricv3_data:
                        retRes[cve_id]['CVSS30']['attackVector'] = basemetricv3_data['attackVector']
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
                        retRes[cve_id]['CVSS30']['baseSeverity'] = basemetricv3_data['baseSeverity']
                    else:
                        retRes[cve_id]['CVSS30']['baseSeverity'] = ''

                    retRes[cve_id]['Reference'] = ','.join(reference_data['data'])

                    retRes[cve_id]['CVSS20'] = {}
                    if 'accessVector' in basemetricv2_data:
                        retRes[cve_id]['CVSS20']['attackVector'] = basemetricv2_data['accessVector']
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
                        retRes[cve_id]['CVSS20']['baseSeverity'] = basemetricv2_data['severity']
                    else:
                        retRes[cve_id]['CVSS20']['baseSeverity'] = ''
                

        query = "select reference, application, cve_id from pocreference_db"
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall();

        print("[ OK ] PoC Table Sync started")

        if len(fetchData) > 0:
            for data in tqdm(fetchData):
                reference = data[0]
                application = data[1]
                cve_id = data[2]

                if cve_id in retRes:
                    if 'Exploits' not in retRes[cve_id]:
                        retRes[cve_id]['Exploits'] = []

                    res = {}
                    res['Advisory'] = application 
                    res['Reference'] = reference

                    if res not in retRes[cve_id]['Exploits']:
                        retRes[cve_id]['Exploits'].append(res)

        print("[ OK ] CVEs feed generation started")
        for cve_id in retRes:
            with open("/var/DB/CVEs/%s.json" % (cve_id), "w") as outfile:
                json.dump(retRes[cve_id], outfile, indent = 2)

        print("[ OK ] languages, plugins feeds generation started")
        for app_type in results:
            for application in results[app_type]:
                res_data = {}
                res_data['publishDate'] = date_update
                res_data['data'] = []

                for cve_id in tqdm(results[app_type][application]):
                    res = results[app_type][application][cve_id]
                    res['cve_id'] = cve_id
                    res['application'] = application
                    res['app_type'] = app_type
                    res['reference'] = retRes[cve_id]['Reference']
                    res['cwe_str'] = self.getCWEText(retRes[cve_id]['CWE'])
                    res['publishedDate'] = retRes[cve_id]['publishedDate']
                    res['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
                    res['description'] = retRes[cve_id]['description']
                    if 'Exploits' in retRes[cve_id]:
                        res['exploits'] = self.get_exploit_str(retRes[cve_id]['Exploits'])
                    else:
                        res['exploits'] = ''        
                    res['cwe_text'] = retRes[cve_id]['CWE']
                    res['baseseverity2'] = retRes[cve_id]['CVSS20']['baseSeverity']
                    res['attackvector2'] = retRes[cve_id]['CVSS20']['attackVector']
                    res['vectorstring2'] = retRes[cve_id]['CVSS20']['vectorString']
                    res['basescore2'] = retRes[cve_id]['CVSS20']['baseScore']
                    res['exploitabilityScore'] = retRes[cve_id]['CVSS20']['exploitabilityScore']
                    res['baseseverity3'] = retRes[cve_id]['CVSS30']['baseSeverity']
                    res['attackvector3'] = retRes[cve_id]['CVSS30']['attackVector']
                    res['vectorstring3'] = retRes[cve_id]['CVSS30']['vectorString']
                    res['basescore3'] = retRes[cve_id]['CVSS30']['baseScore']
                    res['exploitabilityScore3'] = retRes[cve_id]['CVSS30']['exploitabilityScore']

                    if retRes[cve_id]['CVSS30']['attackVector']:
                        res['attackvector'] = retRes[cve_id]['CVSS30']['attackVector']
                    else:
                        res['attackvector'] = retRes[cve_id]['CVSS20']['attackVector']
                    if retRes[cve_id]['CVSS30']['baseSeverity']:
                        res['baseseverity'] = retRes[cve_id]['CVSS30']['baseSeverity']
                    else:
                        res['baseseverity'] = retRes[cve_id]['CVSS20']['baseSeverity']
                    if retRes[cve_id]['CVSS30']['vectorString']:
                        res['vectorstring'] = retRes[cve_id]['CVSS30']['vectorString']
                    else:
                        res['vectorstring'] = retRes[cve_id]['CVSS20']['vectorString']
                    if retRes[cve_id]['CVSS30']['baseScore']:
                        res['basescore'] = retRes[cve_id]['CVSS30']['baseScore']
                    else:
                        res['basescore'] = retRes[cve_id]['CVSS20']['baseScore']
                    
                    res_data['data'].append(res)

                with open("/var/DB/feeds/%s_%s.json" % (application, app_type), "w") as f:
                    json.dump(res_data, f, indent = 2)

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
