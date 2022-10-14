
import requests
from bs4 import BeautifulSoup
import json
import os.path
import re

class ruby_info():
    def __init__(self) -> None:
            pass

    def ruby_scan(self,url):
        urls = []
        r =requests.get(url)
        htmlContent = r.content
        homesoup = BeautifulSoup(htmlContent,'html.parser')

        uv = homesoup.find('div', class_='l-wrap--b')
        for a in uv.findAll('a', class_='gems__gem'):
            if 'href' in a.attrs:
                url = a.get('href')
                packagename = re.findall(r'\/.*\/(.*)', str(url))[0]
                fpath = "/var/DB/packages/ruby/%s.json" % packagename
                print(fpath)
                if os.path.isfile(fpath):
                    print("%s exists" % fpath)
                else:
                    url = 'https://rubygems.org' +url
                    urls.append(url)

        for url in urls:
            print("URL - %s" % url)
            r = requests.get(url)
            htmlContent = r.content
            soup = BeautifulSoup(htmlContent, "html.parser")
           
            data = {}
            package = []
            pname = soup.find('div', class_='l-wrap--b').find('h1').text.strip().replace(" ","")
            p = pname.replace('\n\n', ',')
            package = p.split(",")
           
            p_name = package[0]
            latest_version = package[1]

            p_dis = ''
            if soup.find('div', class_ = "gem__desc"):
                if soup.find('div', class_ = "gem__desc").find('p'):
                    p_dis = soup.find('div', class_ = "gem__desc").find('p').text.strip()

            version_url = url + '/versions'
            r = requests.get(version_url)
            versionContent = r.content
            versionsoup = BeautifulSoup(versionContent, "html.parser")

            v_list = versionsoup.find('div', class_='versions')
            version_list =[]
            for a in v_list.findAll('li'):
                a = a.find('a').text.strip()
                version_list.append(a)

            license = ''

            if soup.find('div', class_="gem__aside l-col--r--pad"):
                details_divs = soup.find('div', class_="gem__aside l-col--r--pad")
                if details_divs.findAll('h2', class_="gem__ruby-version__heading t-list__heading"):
                    h2tags = details_divs.findAll('h2', class_="gem__ruby-version__heading t-list__heading")

                    for h2 in h2tags:
                        if 'License:' in h2.text:
                            license = h2.find('p').text.strip()
            
            r_dependencies = []
            try:
                r_dep = soup.find('div', id='runtime_dependencies').find('div',class_='t-list__items')
                for a in r_dep.findAll('li'):
                    r_dep1 = a.find('a').text.strip()
                    r_dependencies.append(r_dep1)

            except:
                r_dependencies = []


            d_dependencies = []
            try:
                d_dep = soup.find('div', id='development_dependencies').find('div',class_='t-list__items')
                for a in d_dep.findAll('li'):
                    d_dep1 = a.find('a').text.strip()
                    d_dependencies.append(d_dep1)
            except:
                d_dependencies = []

            downloadall = soup.findAll('div', class_="gem__aside l-col--r--pad")[0].findAll('span', class_='gem__downloads')[0]
            downall = downloadall.text.strip()

            downloadthis = soup.findAll('div', class_="gem__aside l-col--r--pad")[0].findAll('span', class_='gem__downloads')[1]
            downthis = downloadthis.text.strip()

            downloads = ({"Total Downloads": downall, "For this version": downthis})
            
            homeurl = ''
            try:
                homeurl = soup.find('div',class_="gem__aside l-col--r--pad").find('div', class_='t-list__items').find('a', class_='gem__link t-list__item', id='home').get('href')
            except:
                homeurl = ''

            downloadurl = ''

            if soup.find('div',class_="gem__aside l-col--r--pad"):
                download_details = soup.find('div',class_="gem__aside l-col--r--pad")
                if download_details.find('div', class_='t-list__items'):
                    download_atags = download_details.find('div', class_='t-list__items')
                    if download_atags.find('a', class_='gem__link t-list__item', id='download'):
                        downloadurl = download_atags.find('a', class_='gem__link t-list__item', id='download').get('href')

            data['packagename'] = p_name
            data['description'] = p_dis
            data['latest_version'] = latest_version
            data['versions'] = version_list
            data['license'] = license
            data['Runtime_Dependencies'] = r_dependencies
            data['Developer_Dependencies'] = d_dependencies
            data['HomeURL'] = homeurl
            data['DownloadURL'] = downloadurl
            data['downloads'] = downloads

            with open("/var/DB/packages/ruby/%s.json" % p_name, "w") as outfile:
                json.dump(data, outfile, indent=2)

            print("%s.json File Created Successfully..!!" %p_name)

    def rssfeed(self):
        page = 1
        while True:
            url = "https://rubygems.org/news?page=%s" % page
            self.ruby_scan(url)
            page = page + 1
            
            if page == 10:
                break

    def find_info(self):
        page = 1
        while True:
            url = "https://rubygems.org/gems?page=%s" % page
            self.ruby_scan(url)
            page = page + 1
            
            if page == 389:
                break


if __name__ == "__main__":
    res = ruby_info()
    res.find_info()



