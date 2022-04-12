from cgitb import reset
from ensurepip import version
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
                                r = {}
                                if 'patch' in detail:
                                    patch = detail['patch']
                                else:
                                    patch = ''
                                if 'version' in detail:
                                    version = detail['version']
                                else:
                                    version = ''
                                if 'platform' in detail:
                                    platform = detail['platform']
                                    r['platform'] = platform
                                
                                if 'advisoryid' in detail:
                                    advisoryid = detail['advisoryid']
                                    r['advisoryid'] = advisoryid

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
        results['platform'] = {}

        pkg_vnd_results = {}
        
        print("[ OK ] vuln Table Sync started")
        cmd = "select distinct(niahid), data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision from vuln_tab ORDER BY revision DESC"
        #cmd = "select distinct(niahid), data_type, data_id, cwe_data, reference_data, description, basemetricv3_data, basemetricv2_data, publisheddate, lastmodifieddate, affected_products_versions, status, vuln_status, revision from vuln_tab where data_id LIKE '%%CVE-2021-%%' ORDER BY revision DESC"

        self.cursor.execute(cmd)
        fetchData = self.cursor.fetchall()
        for row in tqdm(fetchData):
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
                            res['niah_version_id'] = niah_version_id
                            res['niah_product_id'] = niah_product_id
                            

                            if 'language' in detail:
                                res['language'] = detail['language']
                                retRes[cve_id]['library_advisory']['data'].append(res)

                                if detail['language'] not in results['language']:
                                    results['language'][detail['language']] = {}
                                if cve_id not in results['language'][detail['language']]:
                                    results['language'][detail['language']][cve_id] = []
                                if res not in results['language'][detail['language']][cve_id]:
                                    results['language'][detail['language']][cve_id].append(res)
                            
                            if 'plugin' in detail:
                                res['plugin'] = detail['plugin']
                                retRes[cve_id]['plugin_advisory']['data'].append(res)

                                if detail['plugin'] not in results['plugin']:
                                    results['plugin'][detail['plugin']] = {}
                                if cve_id not in results['plugin'][detail['plugin']]:
                                    results['plugin'][detail['plugin']][cve_id] = []

                                if res not in results['plugin'][detail['plugin']][cve_id]:
                                    results['plugin'][detail['plugin']][cve_id].append(res)

                            if type == "platform":
                                if 'advisoryid' in detail:
                                    res['advisoryid'] = detail['advisoryid']
                                res['platform'] = detail['platform']
                                
                                if advisory == "ubuntu":
                                    reference = "https://ubuntu.com/security/%s" % cve_id.upper()
                                    res['family'] = "Ubuntu"
                                    res['Reference'] = reference
                                    retRes[cve_id]['platform_advisory']['data'].append(res)
                                    if 'ubuntu' not in results['platform']:
                                        results['platform']['ubuntu'] = {}
                                    if cve_id not in results['platform']['ubuntu']:
                                        results['platform']['ubuntu'][cve_id] = []
                                    if res not in results['platform']['ubuntu'][cve_id]:
                                        results['platform']['ubuntu'][cve_id].append(res)


                                if advisory == "debian":
                                    reference = "https://security-tracker.debian.org/tracker/%s" % cve_id.upper()
                                    res['family'] = "Debian"
                                    res['Reference'] = reference
                                    retRes[cve_id]['platform_advisory']['data'].append(res)
                                    if 'debian' not in results['platform']:
                                        results['platform']['debian'] = {}
                                    if cve_id not in results['platform']['debian']:
                                        results['platform']['debian'][cve_id] = []
                                    if res not in results['platform']['debian'][cve_id]:
                                        results['platform']['debian'][cve_id].append(res)
                            
                            retRes[cve_id]['Products']['data'].append(res)

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


        fetchData = ''

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
        res_db = {}
        res_tables = []
        fetchData = ''

        for cve_id in retRes:
            with open("/var/DB/CVEs/%s.json" % (cve_id), "w") as outfile:
                json.dump(retRes[cve_id], outfile, indent = 2)

            data_id = retRes[cve_id]['data_id']
            data_type = retRes[cve_id]['data_type']

            if data_type == "CVE":
                year = data_id.split("-")[1]
            else:
                year = publisheddate.split("-")[0]

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
            for pkg in retRes[cve_id]['Products']['data']:
                if pkg['product'] not in res_tab['products']:
                    res_tab['products'].append(pkg['product'])
                if pkg['vendor'] not in  res_tab['vendors']:
                    res_tab['vendors'].append(pkg['vendor'])
                if 'language' in pkg:
                    res_tab['language'] = pkg['language']
                if 'plugin' in pkg:
                    res_tab['plugin'] = pkg['plugin']
                if 'family' in pkg:
                    res_tab['family'] = pkg['family']
                if 'type' in pkg:
                    res_tab['part'] = pkg['type']

            res_db[year][cve_id]['products'] = retRes[cve_id]['Products']['data']
            res_db[year][cve_id]['niahid'] = retRes[cve_id]['niahid']
            res_db[year][cve_id]['cve_id'] = cve_id                    
            res_db[year][cve_id]['application'] = application                   
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
            res_tab['lastModifiedDate'] = retRes[cve_id]['lastModifiedDate']
            res_tables.append(res_tab)

        # Table View data
        with open("/var/DB/feeds/nvd/vuln_feed.json", "w") as f:
            json.dump(res_tables, f, indent = 2)

        res_tables = ''
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

        r_results = ''

        print("[ OK ] languages, plugins and platform feeds generation started")
        for app_type in results:
            if app_type == "platform":
                app_type_lists = {}
                app_type_lists['publishDate'] = date_update
                app_type_lists['data'] = {}

                for application in results[app_type]:
                    res_data = {}
                    res_data['publishDate'] = date_update
                    res_data['data'] = {}
                    res_data['metadata'] = {}

                    for cve_id in tqdm(results[app_type][application]):
                        res_data['metadata'][cve_id] = retRes[cve_id]
                        packages_details = results[app_type][application][cve_id]

                        for pkg in packages_details:
                            platform = pkg['platform']
                            if platform not in res_data['data']:
                                res_data['data'][platform] = {}

                            product = pkg['product']
                            if product not in res_data['data'][platform]:
                                res_data['data'][platform][product] = []
                            
                            if pkg not in res_data['data'][platform][product]:
                                res_data['data'][platform][product].append(pkg)

                    with open("/var/DB/feeds/%s/%s_feeds.json" % (app_type, application), "w") as f:
                        json.dump(res_data, f, indent = 2)

                with open("/var/DB/feeds/%s/%s.json" % (app_type, app_type), "w") as f:
                    json.dump(res_data, f, indent = 2)

            
            if app_type == "plugin" or app_type == "language" or app_type == "platform":
                app_type_lists = {}
                app_type_lists['publishDate'] = date_update
                app_type_lists['data'] = []

                for application in results[app_type]:
                    res_data = {}
                    res_data['publishDate'] = date_update
                    res_data['data'] = []
                    res_data['metadata'] = {}

                    for cve_id in tqdm(results[app_type][application]):    
                        res_data['metadata'][cve_id] = retRes[cve_id]
                        
                        packages_details = results[app_type][application][cve_id]
                        for pkg in packages_details:
                            res = pkg
                            res['niahid'] = retRes[cve_id]['niahid']
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

                            if res not in app_type_lists['data']:
                                app_type_lists['data'].append(res)
                        
                    with open("/var/DB/feeds/%s/%s.json" % (app_type, application), "w") as f:
                        json.dump(res_data, f, indent = 2)
                
                with open("/var/DB/feeds/%s/%s.json" % (app_type, app_type), "w") as f:
                    json.dump(res_data, f, indent = 2)


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
