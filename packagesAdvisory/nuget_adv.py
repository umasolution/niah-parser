import requests
from bs4 import BeautifulSoup
import json
import time
import re
import os.path

class nuget_info():
    def __init__(self) -> None:
            pass

    def nuget_scan(self,url):
        r =requests.get(url)
        htmlContent = r.content
        homesoup = BeautifulSoup(htmlContent,'html.parser')
        urls = []

        uv = homesoup.find('div', class_='list-packages')
        for a in uv.findAll('a',class_='package-title'):
            if 'href' in a.attrs:
                url = a.get('href')
                packagename = ''

                if re.findall(r'\/packages\/(.*)\/.*', str(url)):
                    packagename = re.findall(r'\/packages\/(.*)\/.*', str(url))[0]

                if packagename:
                    fpath = "/var/DB/packages/nuget/%s.json" % packagename
                    print(fpath)
                    if os.path.isfile(fpath):
                        print("%s exists" % fpath)
                    else:
                        url = 'https://www.nuget.org' +url
                        urls.append(url)
                else:
                    url = 'https://www.nuget.org' +url
                    urls.append(url)
            
        for url in urls:
            time.sleep(2)
            print("URL - %s" % url)
            r = requests.get(url)
            htmlContent = r.content
            soup = BeautifulSoup(htmlContent, "html.parser")
            data = {}
            
            p_name = soup.find('div', class_='package-title').find('span', class_='title').text.strip()
            print("packagename - %s" % p_name)
            latest_version = soup.find('div', class_='package-title').find('span', class_='version-title').text.strip()
        
            try:
                p_dis = soup.find('div', id = "readme-tab").find('p').text.strip()
            except:
                p_dis = ''

            v_list = soup.find('div', class_='version-history').find('tbody', class_='no-border')
            version_list =[]
            for a in v_list.findAll('tr'):
                a = a.find('a').text.strip()
                version_list.append(a)

            pro_web = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[1].find('a').get('href')

            source_repo = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[2].find('a').get('href')

            license = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[3].find('a').text.strip()
            
            downloadurl = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[4].find('a').get('href')

            dependencies =[]
            try:
                dep = soup.find('div', id ='dependencies-tab').find('ul', id ='dependency-groups')
                for a in dep.findAll('a'):
                    dep1 = a.text.strip()
                    dependencies.append(dep1)
            except:
                dependencies = []

            downloadall = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[0].find('span',class_='download-info-content')
            downall = downloadall.text.strip()

            downloadcurrent = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[1].find('span',class_='download-info-content')
            downcurrent = downloadcurrent.text.strip()

            downloadavg = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[2].find('span',class_='download-info-content')
            downavg = downloadavg.text.strip()

            downloads = ({"Total Downloads:-": downall, "Current Version:-": downcurrent, "Per Day Average:-": downavg})

            data['packagename'] = p_name
            data['description'] = p_dis
            data['latest-version'] = latest_version
            data['versions'] = version_list
            data['project-website'] = pro_web
            data['Source-repo'] = source_repo
            data['license'] = license
            data['Dependencies'] = dependencies
            data['DownloadURL'] = downloadurl
            data['downloads'] = downloads

            with open("/var/DB/packages/nuget/%s.json" % p_name, "w") as outfile:
                json.dump(data, outfile, indent=2)

            print("%s.json File Created Successfully..!!" %p_name)

            
    def find_info(self):

        url = "https://www.nuget.org/"
        page = 1
        while True:

            url = "https://www.nuget.org/packages?page=%s" %page
            self.nuget_scan(url)
            page = page + 1

            if page > 1505:
                    break


if __name__ == "__main__":
    res = nuget_info()
    res.find_info()
