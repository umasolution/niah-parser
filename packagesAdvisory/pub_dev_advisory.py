from importlib.resources import Package
import requests
import re
from bs4 import BeautifulSoup
import json
import sys
import array

class pub_dev_advisory():
    def __init__(self) -> None:
        pass

    def find_data(self, url):
        page = requests.get(url)
        response = page.content
        soup = BeautifulSoup(response,"html.parser")
        result = {}
        urls = []
        main_urls = soup.find('div',class_ = 'packages')
        for h3 in main_urls.findAll('h3'):
            a_tag = h3.find('a')
            try:   
                if 'href' in a_tag.attrs:
                    url = a_tag.get('href')
                    url = 'https://pub.dev' +url
                    urls.append(url)
            except:
                pass
        
        for url in urls:
            page = requests.get(url)
            response = page.content
            soup = BeautifulSoup(response,"html.parser")
            version_url = url + '/versions'
            
            r = requests.get(version_url)
            versionContent = r.content
            versionsoup = BeautifulSoup(versionContent, "html.parser")

            versions = []
        
            vlist = versionsoup.find('table', class_ = 'version-table').find('tbody')

            for table in vlist.findAll('tr'):
                ver = table.find('td').find('a').text
                versions.append(ver)
                
            l_version = versions[0]

            Package_name = re.findall(r'https:\/\/pub.dev\/packages\/(.*)',str(url))[0]

            div = soup.find('div', class_ = 'detail-container').find('div', class_ = 'detail-tags')

            sdk_types = []
            sdk_type = div.find('div', class_ = '-pub-tag-badge').findAll('a')
            for sdk in sdk_type:
                sdk_types.append(sdk.text)

            a_tag = soup.find('aside', class_ = 'detail-info-box').find('a')

            try:
                likes = a_tag.find('div', class_ = 'packages-score packages-score-like').text.replace("likes", "")
            except:
                likes = ''

            pub_points = a_tag.find('div', class_ = 'packages-score packages-score-health').text.replace("pub points", "")

            popularity = a_tag.find('div', class_ = 'packages-score packages-score-popularity').text.replace("%popularity", "")

            description = soup.find('aside',class_ = 'detail-info-box').findAll("p")[1]
            des = description.text

            link = soup.find('aside',class_ = 'detail-info-box').findAll("p")[2]

            if link.find('a'):
                home_url = link.find('a').get('href')
                if 'github' in home_url:
                    git_link = home_url
                else:
                    git_link = ''
            else:
                home_url = ''
                git_link = ''

            license = soup.find('aside',class_ = 'detail-info-box').findAll("p")[4]
            lic = license.text

            depends = []
            dependencies = soup.find('aside',class_ = 'detail-info-box').findAll("p")[5]

            dep_url = dependencies.findAll('a')
            for dep in dep_url:
                if 'https' in dep.get('href'):
                    depends.append(dep.text)
        
            
            result['package_name'] = Package_name
            result['sdk'] = sdk_types
            result['likes'] = likes
            result['points'] = pub_points
            result['populirity'] = popularity
            result['description'] = des
            result['version'] = versions
            result['latest_version'] = l_version
            result['github_url'] = git_link
            result['home_url'] = home_url
            result['license'] = lic
            result['dependencies'] = depends
        
            with open("output\%s.json" % Package_name, "w") as outfile:
                json.dump(result, outfile, indent=2)

            print("%s.json file created completely.....!!!!!! " %Package_name)

    def rssfeed(self):      
        url = "https://pub.dev/packages?q=sdk&sort=created"
        self.find_data(url)

        url = "https://pub.dev/packages?q=sdk&sort=updated"
        self.find_data(url)
            
    def main(self):
        url = "https://pub.dev/packages?q=sdk"
        page = 1
        while True:        
            url = "https://pub.dev/packages?q=sdk&page=%s" %page
            self.find_data(url)
            page = page + 1
        
            if page > 373:
                break


if __name__ == "__main__":
    res = pub_dev_advisory()
    res.main()