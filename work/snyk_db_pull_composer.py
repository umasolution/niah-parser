from struct import pack
from bs4 import BeautifulSoup
from lib.dateConvert import dateConvert
import datetime
import json
import time
import requests
import re
import sys
import time
import json
import psycopg2
import os
import configparser
from tqdm import tqdm

class snyk_db():
    def __init__(self):
        pass

    def convertVersion(self, version):
                versionNos = version

                results = []
                for vers in re.findall(r'((\[|\().*?(\)|\]))', str(versionNos)):
                    try:
                        if re.findall(r'\[(.*)\)', str(vers[0])):
                                verStr = re.findall(r'\[(.*)\)', str(vers[0]))[0]
                                ver1 = verStr.split(",")[0].strip()
                                ver2 = verStr.split(",")[1].strip()
                                if ver1 == "0" and not ver2:
                                        ver = "*"
                                elif ver1 and not ver2:
                                        ver = "[%s:99.99.99)" % ver1
                                elif not ver1 and ver2:
                                        ver1 = "0.0"
                                        ver = "[%s:%s)" % (ver1, ver2)
                                else:
                                        ver = "[%s:%s)" % (ver1, ver2)

                        elif re.findall(r'\[(.*)\]', str(vers[0])):
                                verStr = re.findall(r'\[(.*)\]', str(vers[0]))[0]
                                if len(verStr.split(",")) > 1:
                                        ver1 = verStr.split(",")[0].strip()
                                        ver2 = verStr.split(",")[1].strip()
                                        if ver1 == "0" and not ver2:
                                                ver = "*"
                                        elif ver1 and not ver2:
                                                ver = "[%s:99.99.99]" % ver1
                                        elif not ver1 and ver2:
                                                ver = "[0.0:%s]" % ver2
                                        elif ver1 and ver2:
                                                ver = "[%s:%s]" % (ver1, ver2)
                                else:
                                        ver = verStr

                        elif re.findall(r'\((.*)\)', str(vers[0])):
                                verStr = re.findall(r'\((.*)\)', str(vers[0]))[0]
                                if len(verStr.split(",")) > 1:
                                        ver1 = verStr.split(",")[0].strip()
                                        ver2 = verStr.split(",")[1].strip()
                                        if ver1 == "0" and not ver2:
                                                ver = "*"
                                        elif ver1 and not ver2:
                                                ver = "(%s:99.99.99]" % ver1
                                        elif not ver1 and ver2:
                                                ver = "[0.0:%s)" % ver2
                                        elif ver1 and ver2:
                                                ver = "(%s:%s)" % (ver1, ver2)
                                else:
                                        ver = verStr

                        elif re.findall(r'\((.*)\]', str(vers[0])):
                                verStr = re.findall(r'\((.*)\]', str(vers[0]))[0]
                                if len(verStr.split(",")) > 1:
                                        ver1 = verStr.split(",")[0].strip()
                                        ver2 = verStr.split(",")[1].strip()
                                        if ver1 == "0" and not ver2:
                                                ver = "*"
                                        elif ver1 and not ver2:
                                                ver = "(%s:99.99.99]" % ver1
                                        elif not ver1 and ver2:
                                                ver = "[0.0:%s]" % ver2
                                        elif ver1 and ver2:
                                                ver = "(%s:%s]" % (ver1, ver2)
                                else:
                                        ver = verStr

                        elif re.findall(r'\[(.*)\)', str(vers[0])):
                                verStr = re.findall(r'\[(.*)\)', str(vers[0]))[0]
                                if len(verStr.split(",")) > 1:
                                        ver1 = verStr.split(",")[0].strip()
                                        ver2 = verStr.split(",")[1].strip()
                                        if ver1 == "0" and not ver2:
                                                ver = "*"
                                        elif ver1 and not ver2:
                                                ver = "[%s:99.99.99]" % ver1
                                        elif not ver1 and ver2:
                                                ver = "[0.0:%s)" % ver2
                                        elif ver1 and ver2:
                                                ver = "[%s:%s)" % (ver1, ver2)
                                else:
                                        ver = verStr
                        else:
                                ver = "*"


                        results.append(ver)
                    except:
                        ver = "*"
                        results.append(ver)

                return ','.join(results)

    def fetch_packages_details(self, packagename, url, vendor, product):
        page = requests.get(url)
        soup = BeautifulSoup(page.text, "html.parser")
        
        github = ''

        home_url = "https://packagist.org/packages/%s/%s" % (vendor, product)
        results = {}
        results['packagename'] = packagename
        results['url'] = url
        results['home_url'] = home_url
        results['vendor'] = vendor
        results['product'] = product
        results['vulns'] = []
        for tabl in soup.findAll('table', {'class':'table--comfortable'}):
            i = 0
            for tr in tqdm(tabl.findAll('tr')):
                if i == 0:
                    i = i + 1
                else:
                    res = {}
                    tds = tr.findAll('td')
                    span_text = tds[0].findAll('span', {'class':'l-push-left--sm'})
                    a_url = span_text[0].findAll('a')[0].get('href')
                    vuln_name = span_text[0].text.strip()
                    version_str = tds[1].text.strip()
                    versions = self.convertVersion(version_str)
                    pub_date = tds[3].text.strip()
                    try:
                        res1 = dateConvert()
                        pub_date = res1.dateCon(pub_date)
                    except:
                        pub_date = pub_date

                    vuln_details = self.vuln_details(a_url)
                    res['vuln_name'] = vuln_name
                    res['versions'] = versions
                    res['pub_date'] = pub_date
                    res['cves'] = vuln_details['cves']
                    res['cweid'] = vuln_details['cweid']
                    res['severity'] = vuln_details['severity']
                    res['score'] = vuln_details['score']
                    res['reference'] = vuln_details['reference']
                    results['vulns'].append(res)
                    github = vuln_details['github']

        if github:
            results['github'] = github

        return results

    def unique(self, list1): 
        # insert the list to the set
        list_set = set(list1)
        # convert the set to the list
        unique_list = (list(list_set))
        for x in unique_list:
            return x,

    def vuln_details(self, url):
        commit_url = ''

        res = {}
        url = "https://security.snyk.io%s" % url
        page = requests.get(url)
        soup = BeautifulSoup(page.text, "html.parser")

        cves = re.findall(r'(CVE-\d+-\d+)', str(soup.encode('ascii', 'ignore').decode('ascii')), re.IGNORECASE)
        cves = self.unique(cves)
        
        github = ''
        for url_refe in soup.findAll('div', {'class': 'vue--markdown-to-html markdown-description'}):
            for atag in url_refe.findAll('a'):
                if 'GitHub' in atag.text:
                    commit_url = atag.get('href')
                    github = '/'.join(commit_url.split("/")[0:5])

        if soup.findAll('a', {'class': 'vue--anchor'}):
            cwe_text = soup.findAll('a', {'class': 'vue--anchor'})[1].text.strip()
        else:
            cwe_text = ''
        if re.findall(r'(CWE-\d+)', str(soup)):
            cwe_text = re.findall(r'(CWE-\d+)', str(soup))[0]
        else:
            cwe_text = ''
        if re.findall(r'data-snyk-test-score="(.*?)"', str(soup)):
            score = re.findall(r'data-snyk-test-score="(.*?)"', str(soup))[0]
        else:
            score = ''

        severity = "MEDIUM"

        res['vuln_url'] = url
        res['cves'] = cves
        res['github'] = github
        res['cweid'] = cwe_text
        res['severity'] = severity
        res['score'] = score
        res['reference'] = commit_url
        return res
        
    def indialize(self):
        packages = []
        results = []

        i = 1
        while True:
            url = "https://security.snyk.io/vuln/composer/%s" % i
            page = requests.get(url)
            soup = BeautifulSoup(page.text, "html.parser")

            for tabls in soup.findAll('table', {'class': 'vue--table vulns-table__table'}):
                j = 0
                for tr in tabls.findAll('tr'):
                    if j == 0:
                        j =j + 1
                    else:
                        try:
                                tds = tr.findAll('td')
                                a_tag = tds[1].findAll('a')[0].get('href')
                                a_tag_regex = re.findall(r'https:\/\/snyk\.io\/vuln\/composer%3A(.*)%2F(.*)', str(a_tag))
                                vendor = a_tag_regex[0][0]
                                product = a_tag_regex[0][1]
                                packagename = "%s/%s" % (vendor, product)
                                if packagename not in packages:
                                        packages.append(packagename)
                                        print(packagename)
                                        res = self.fetch_packages_details(packagename, a_tag, vendor, product)
                                        results.append(res)
                        except:
                                pass
            i = i + 1
            if i == 120:
                break
        
        with open("composer_vulns.json", "w") as f:
            json.dump(results, f, indent=4)

        

if __name__ == "__main__":
    res = snyk_db()
    res.indialize()
    #res.fetch_packages_details()
    #res.vuln_details('https://security.snyk.io/vuln/SNYK-JAVA-ORGELASTICSEARCH-1324572')