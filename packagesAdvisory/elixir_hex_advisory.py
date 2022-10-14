
import requests
from bs4 import BeautifulSoup
import json
import os.path



class elixir_hex_advisory():
    def __init__(self) -> None:
        pass

    def find_data(self, url):        
        r = requests.get(url)
        htmlContent = r.content
        soup = BeautifulSoup(htmlContent,'html.parser')
        urls = []
        uv = soup.find('div',class_ = 'package-list')
        for h in uv.findAll('li'):
            a = h.find('a')
            packagename = a.text

            fpath = "/var/DB/packages/hex/%s.json" % packagename
            if os.path.isfile('filename.txt'):
                print("%s exists" % fpath)
            else:
                try:
                    if 'href' in a.attrs:
                        url = a.get('href')
                        url = 'https://hex.pm/' +url
                        urls.append(url)
                except:
                        pass
        
        for url in urls:
            print("url - %s" % url)
            r = requests.get(url)
            htmlContent = r.content
            soup = BeautifulSoup(htmlContent, "html.parser")
                
            version_url = url + '/versions'
            r = requests.get(version_url)
            versionContent = r.content
            versionsoup = BeautifulSoup(versionContent, "html.parser")
                
            versions = []
            vlist = versionsoup.find('div',class_ = 'version-list')
            for a in vlist.findAll('li'):
                ver = a.find('a').text.strip()
                versions.append(ver)

            dependencies = []
            dep = soup.find('div', class_='col-md-9 no-padding').findAll('div',class_='col-md-11 with-divider no-padding')[2].findAll('div',class_ = 'col-md-6 no-padding')[1]
            for a in dep.findAll('li'):
                dep1 = a.find('a').text.strip()
                dependencies.append(dep1)

            p_name = soup.find('div', class_='container package-view').find('a').text


            if soup.find('div',class_ = "description with-divider"):
                p_dis = soup.find('div',class_ = "description with-divider").find('p').text
            else:
                p_dis = ''

        
            download1 = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[1]
            down1 = download1.text.strip()

            download7 = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[2]
            down7 = download7.text.strip()

            downloadall = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[3]
            downall = downloadall.text.strip()

            downloads = ({"yesterday:": down1, "last 7 day :": down7, "all time:": downall})
            latest_version = soup.find('span', class_="version").text

            if soup.find('span', class_="license"):
                license = soup.find('span', class_="license").text
            else:
                license = ''

            github_url = soup.find('div',class_='col-md-9 no-padding').find('div',class_='col-md-11 with-divider no-padding')
            g_url = ''
            if len(github_url.findAll('li')) > 1:
                for anchor in github_url.findAll('li')[1]:
                    g_url = anchor.get('href')

            data = {}
            data['packagename'] = p_name
            data['description'] = p_dis
            data['latest_version'] = latest_version
            data['versions'] = versions
            data['license'] = license
            data['Dependencies'] = dependencies
            data['github_url'] = g_url
            data['downloads'] = downloads

            with open("/var/DB/packages/hex/%s.json" % p_name, "w") as outfile:
                    json.dump(data, outfile, indent=2)
                
            print("%s.json File Created Successfully..!!" %p_name)


    def find_info(self):
        url = "https://hex.pm/packages"
        page = 1
        while True:
            url = "https://hex.pm/packages?page=%s" %page
            self.find_data(url)
            page = page + 1

            if page > 455:
                    break

    def rssfeed(self):
        url = "https://hex.pm/packages?sort=inserted_at"
        self.find_data(url)

        url = "https://hex.pm/packages?sort=updated_at"
        self.find_data(url)
        

if __name__ == "__main__":
    res = elixir_hex_advisory()
    res.find_info()

