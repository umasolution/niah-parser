from platform import platform
from textwrap import indent
import requests
from bs4 import BeautifulSoup
import re
import json
import os
import sys
import datetime
import configparser
import time
import urllib
from tqdm import tqdm
from glob import glob
import argparse

class get_license():
    def __init__(self):
        pass

    def gen_pypi_license(self, date_update):
        print("[ OK ] Pypi License generation")
        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/pypi/*.json')):
            if 'level-' not in f_name:
                with open(f_name, "r") as f:
                    data = json.load(f)

                tagname = data['info']['name']
                license = data['info']['license']
                results['data'][tagname] = license

        with open("/var/DB/feeds/packages/pypi_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)
        
    def pypiParser(self, package):
        try:
            url = 'https://pypi.org/pypi/%s/json' % package
            response = urllib.request.urlopen(url)
            data = json.load(response)
            license = data['info']['license']
            return license
        except:
            return False

    def gen_composer_license(self, date_update):
        print("[ OK ] Composer License generation")
        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/composer/*.json')):
            if 'level-' not in f_name:
                with open(f_name, "r") as f:
                    data = json.load(f)

                if 'vendor' in data:
                    vendor = data['vendor']
                else:
                    vendor = ''

                product = data['product']
                if product and vendor:
                    tagname = "%s/%s" % (vendor, product)
                else:
                    tagname = product

                try:
                    if 'current' in data:
                        if len(data['current']['license']) > 0:
                            if len(data['current']['license']) > 1:
                                license = ','.join(data['current']['license'])
                            else:
                                license = data['current']['license'][0]
                        else:
                            license = "UNKNOWN"
                    else:
                        license = "UNKNOWN"
                except:
                    license = "UNKNOWN"

                results['data'][tagname] = license

        with open("/var/DB/feeds/packages/composer_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)

    def composerParser(self, package):
        try:
            url = 'https://repo.packagist.org/p2/%s.json' % package
            response = urllib.request.urlopen(url)
            data = json.load(response)
            license = data['packages'][package][0]['license'][0]
            return license
        except:
            return False


    def gen_npm_license(self, date_update):
        print("[ OK ] NPM License generation")
        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/npm/*.json')):
            if 'level-' not in f_name:
                with open(f_name, "r") as f:
                    data = json.load(f)

                if 'current' in data:
                    license = data['current']['license']
                elif 'license' in data:
                    license = data['license']
                
                if 'current' in data:
                    tagname = data['current']['name']
                else:
                    tagname = data['name']

                results['data'][tagname] = license

        with open("/var/DB/feeds/packages/npm_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)

    def npmParser(self, package):
        try:
            url = 'https://registry.npmjs.org/%s' % package
            response = urllib.request.urlopen(url)
            data = json.load(response)
            license = data['license']
            return license
        except:
            return False
    
    def getPageSource(self, url):
        time.sleep(0.3)
        response = requests.get(url)
        return response.text

    def get_json_metadata_json(self, url):
        page_src = self.getPageSource(url)
        xml_parser = BeautifulSoup(page_src, "xml")
        
        versions_lists = xml_parser.find_all('version')
        if xml_parser.find('latest'):
            latest_version = xml_parser.find('latest').contents[0]
        else:
            latest_version = ''

        versions = {}
        if xml_parser.find('groupId') and xml_parser.find('artifactId'):
            versions['groupId'] = xml_parser.find('groupId').contents[0]
            versions['artifactId'] = xml_parser.find('artifactId').contents[0]
            versions['latest'] = latest_version
            versions['all'] = []
        else:
            return False

        for vers in versions_lists:
            version = vers.text
            versions['all'].append(version)

        return versions

    def get_json_xml(self, url):
        page_src = self.getPageSource(url)
        xml_parser = BeautifulSoup(page_src, "xml")

        results = {}

        if xml_parser.find('groupId'):
            groupid = xml_parser.find('groupId').contents[0]
            results['groupid'] = groupid
        
        if xml_parser.find('artifactId'):
            artifactId = xml_parser.find('artifactId').contents[0]
            results['artifactId'] = artifactId

        try:
            if xml_parser.find('description'):
                description = xml_parser.find('description').contents[0]
                results['description'] = description
        except:
            results['description'] = ''
        if xml_parser.find('name'):
            try:
                name = xml_parser.find('name').contents[0]
                results['name'] = name
            except:
                name = ''
                results['name'] = name
        if xml_parser.find('packaging'):
            packaging = xml_parser.find('packaging').contents[0]
            results['packaging'] = packaging
        if xml_parser.find('version'):
            version = xml_parser.find('version').contents[0]
            results['version'] = version
        try:
            if xml_parser.find('url'):
                url_src = xml_parser.find('url').contents[0]
                results['url_src'] = url_src
        except:
            results['url_src'] = ''
        if xml_parser.find('modelVersion'):
            modelVersion = xml_parser.find('modelVersion').contents[0]
            results['modelVersion'] = modelVersion
        if xml_parser.find('license'):
            licenses = xml_parser.find('license')
            results['license'] = {}
            if licenses.find('name'):
                results['license']['name'] = licenses.find('name').text
            if licenses.find('url'):
                results['license']['url'] = licenses.find('url').text

        dependencies = []
        if xml_parser.find_all('dependency'):
            dependency = xml_parser.find_all('dependency')
            
            for dep in dependency:
                res = {}
                if dep.find('groupId'):
                    res['groupId'] = dep.find('groupId').text
                if dep.find('artifactId'):
                    res['artifactId'] = dep.find('artifactId').text
                if dep.find('version'):
                    res['version'] = dep.find('version').text
                dependencies.append(res)

        results['dependencies'] = dependencies

        if xml_parser.find('scm'):
            scm = xml_parser.find('scm')
            results['scm'] = {}
            if scm.find('url'):
                results['scm']['url'] = scm.find('url').text.strip()
            if scm.find('connection'):
                results['scm']['connection'] = scm.find('connection').text.strip()
            if scm.find('developerConnection'):
                results['scm']['developerConnection'] = scm.find('developerConnection').text.strip()

        return results

    def gen_maven_license(self, date_update):
        print("[ OK ] MAVEN License generation")
        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/maven/*.json')):
            if 'level-' not in f_name:
                with open(f_name, "r") as f:
                    data = json.load(f)

                if 'versions' in data:
                    versions_lists = data['versions']
                    for version in versions_lists:
                        if 'groupid' in versions_lists[version]:
                            groupid = versions_lists[version]['groupid']
                            if 'artifactId' in versions_lists[version]:
                                artifactId = versions_lists[version]['artifactId']
                                if 'license' in versions_lists[version]:
                                    if 'name' in versions_lists[version]['license']:
                                        license = versions_lists[version]['license']['name']
                                        license = self.check_license_str(license)
                                        if not license:
                                            license = 'UNKNOWN'
                                    else:
                                        license = 'UNKNOWN'
                                else:
                                    license = 'UNKNOWN'

                                if groupid not in results['data']:
                                    results['data'][groupid] = {}

                                if artifactId not in results['data']:
                                    results['data'][groupid][artifactId] = license
                
        with open("/var/DB/feeds/packages/maven_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)

    def mavenParser(self, groupId, artifactId):
        license = ''

        url = "https://repo1.maven.org/maven2/%s/%s/maven-metadata.xml" % (groupId.replace(".", "/"), artifactId) 
        print(url)
        versions = self.get_json_metadata_json(url)

        if versions:
            if versions['latest']:
                url = "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom" % (groupId.replace(".", "/"), artifactId, versions['latest'], artifactId, versions['latest'])
                print(url)
                data = self.get_json_xml(url)
                if 'license' in data:
                    license = data['license']['name']
                    license_url = data['license']['url']
            else:
                if len(versions['all']) > 0:
                    url = "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom" % (groupId.replace(".", "/"), artifactId, versions['all'][0], artifactId, versions['all'][0])
                    print(url)
                    data = self.get_json_xml(url)
                    if 'license' in data:
                        license = data['license']['name']
                        license_url = data['license']['url']

        if license:
            license_str = self.check_license_str(license, license_url)
            if license_str:
                return license_str
                
        return license	
    

    def check_license_str(self, license_str, license_url=''):
        if license_url:
            if re.findall(r'licenses\/(.*)\.', str(license_url)):
                license_url_text = re.findall(r'licenses\/(.*)\.', str(license_url))[0]
            else:
                license_url_text = ''

        with open("tool/license.json", "r") as f:
            fdata = json.load(f)
        
        for data in fdata:
            key_str = str(data['key'])
            url = data['url']
            try:
                if key_str.lower() in license_str.lower():
                    return key_str
            except:
                if key_str in license_str:
                    return key_str

            if license_url:
                if license_url_text.lower() in url.lower():
                    return key_str

        return False


    def gen_debian_license(self, date_update):
        github_array = {}
        github_array['data'] = []

        print("[ OK ] Debian License generation")
        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/platforms/debian/*/*/copyright.txt')):
            print(f_name)
            if re.findall(r'\/var\/DB\/packages\/platforms\/debian\/.*\/(.*)\/copyright.txt', str(f_name)):
                packagename = re.findall(r'\/var\/DB\/packages\/platforms\/debian\/.*\/(.*)\/copyright.txt', str(f_name))[0]
            else:
                packagename = ''

            if re.findall(r'\/var\/DB\/packages\/platforms\/debian\/(.*)\/.*\/copyright.txt', str(f_name)):
                platform = re.findall(r'\/var\/DB\/packages\/platforms\/debian\/(.*)\/.*\/copyright.txt', str(f_name))[0]
            else:
                platform = ''

            with open(f_name, "r") as f:
                fdata = f.read()

            license_text = ''

            if re.findall(r'License\:\s(.*)', str(fdata)):
                license_text = re.findall(r'License\:\s(.*)', str(fdata))[0]
            else:             
                license_text = self.check_license_str(fdata)
            
            if packagename and platform:
                if platform not in results['data']:
                    results['data'][platform] = {}
            
                results['data'][platform][packagename] = license_text

            if re.findall(r'Source:\s(http.*)', str(fdata)):
                github_url = re.findall(r'Source:\s(http.*)', str(fdata))[0]
            
                res = {}
                res['packagename'] = packagename
                res['platform'] = platform
                res['license'] = license_text
                res['github'] = github_url

                github_array['data'].append(res)

        with open("/var/DB/feeds/packages/debian_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)

        with open("/var/DB/feeds/packages/debian_source.json", "w") as outfile:
            json.dump(github_array, outfile, indent=2)

    def gen_ubuntu_license(self, date_update):
        print("[ OK ] Ubuntu License generation")
        github_array = {}
        github_array['data'] = []

        results = {}
        results['update'] = date_update
        results['data'] = {}

        for f_name in tqdm(glob('/var/DB/packages/platforms/ubuntu/*/*/copyright.txt')):
            print(f_name)
            if re.findall(r'\/var\/DB\/packages\/platforms\/ubuntu\/.*\/(.*)\/copyright.txt', str(f_name)):
                packagename = re.findall(r'\/var\/DB\/packages\/platforms\/ubuntu\/.*\/(.*)\/copyright.txt', str(f_name))[0]
            else:
                packagename = ''

            if re.findall(r'\/var\/DB\/packages\/platforms\/ubuntu\/(.*)\/.*\/copyright.txt', str(f_name)):
                platform = re.findall(r'\/var\/DB\/packages\/platforms\/ubuntu\/(.*)\/.*\/copyright.txt', str(f_name))[0]
            else:
                platform = ''

            with open(f_name, "r") as f:
                fdata = f.read()

            license_text = ''

            if re.findall(r'License\:\s(.*)', str(fdata)):
                license_text = re.findall(r'License\:\s(.*)', str(fdata))[0]
            else:             
                license_text = self.check_license_str(fdata)
            
            if not license_text:
                license_text = ''

            if packagename and platform:
                if platform not in results['data']:
                    results['data'][platform] = {}
            
                results['data'][platform][packagename] = license_text

            if re.findall(r'Source:\s(http.*)', str(fdata)):
                github_url = re.findall(r'Source:\s(http.*)', str(fdata))[0]
            
                res = {}
                res['packagename'] = packagename
                res['platform'] = platform
                res['license'] = license_text
                res['github'] = github_url

                github_array['data'].append(res)

        with open("/var/DB/feeds/packages/ubuntu_license.json", "w") as outfile:
            json.dump(results, outfile, indent=2)

        with open("/var/DB/feeds/packages/ubuntu_source.json", "w") as outfile:
            json.dump(github_array, outfile, indent=2)


if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")

    res = get_license()
    #groupId = "com.apachat"
    #artifactId = "primecalendar"
    #print(res.mavenParser(groupId, artifactId))
    #res.npmParser(package)
    #res.pypiParser(package)
    #res.composerParser(package)

    res.gen_pypi_license(date_update)
    res.gen_composer_license(date_update)
    res.gen_npm_license(date_update)
    res.gen_maven_license(date_update)
    res.gen_ubuntu_license(date_update)
    res.gen_debian_license(date_update)

    