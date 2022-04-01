from bs4 import BeautifulSoup
import requests
import re
import json
import os
import sys
import datetime
import configparser
import time
import urllib
from tqdm import tqdm
import argparse

class composer_parser():
    def __init__(self):
        pass

    def composerParser(self, url_name, url):
        try:
            dirName = url_name.split("/")[0] + "_" + url_name.split("/")[1]

            response = urllib.request.urlopen(url)
            data = json.load(response)

            vendor = url_name.split("/")[0]
            product = url_name.split("/")[1]

            if os.path.exists("composer/%s.json" % dirName):
                with open("composer/%s.json" % dirName, "r") as f:
                    results_json = json.load(f)
            else:
                results_json = {}
                results_json['product'] = product
                results_json['vendor'] = vendor
                results_json['versions'] = {}

            i = 0

            for info in data["packages"][f"{url_name}"]:
                version = info['version']

                if version not in results_json['versions']:
                    results_json['versions'][version] = {}

                    if 'name' in info:
                        name = info["name"]
                    else:
                        name = ""

                    if 'description' in info:
                        description = info["description"]
                    else:
                        description = ""

                    if 'homepage' in info:
                        homepage = info["homepage"]
                    else:
                        homepage = ''

                    if 'license' in info:
                        license = info["license"]
                    else:
                        license = []

                    if 'authors' in info:
                        authors = info["authors"]
                    else:
                        authors = []

                    require = []

                    if 'require' in info:
                        for k, v in info['require'].items():
                            res = {}
                            res['package'] = k
                            res['version'] = v
                            require.append(res)

                    if 'source' in info:
                        source = info["source"]
                    else:
                        source = {}

                    if 'dist' in info:
                        github_api = info["dist"]
                    else:
                        github_api = {}

                    results_json['versions'][version]["name"] = name
                    results_json['versions'][version]["version"] = version
                    results_json['versions'][version]["description"] = description
                    results_json['versions'][version]["homepage"] = homepage
                    results_json['versions'][version]["license"] = license
                    results_json['versions'][version]["github"] = homepage
                    results_json['versions'][version]["author"] = authors
                    results_json['versions'][version]["require"] = require
                    results_json['versions'][version]["source"] = source
                    results_json['versions'][version]["github_api"] = github_api

                if i == 0:
                    results_json['current'] = results_json['versions'][version]
                    i = i + 1

            with open("composer/%s.json" % dirName, "w") as outfile:
                json.dump(results_json, outfile)
        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {url}")


    def startParsing(self, fullscan):
        if fullscan == "yes":
            if not os.path.exists('composer_data.json'):
                url = "https://packagist.org/packages/list.json"
                page = requests.get(url)
                jsonData = page.json()

                with open("composer_data.json", "w") as f:
                    json.dump(jsonData, f, indent=4)

            with open("composer_data.json", "r") as f:
                out_data = json.load(f)

            i = 0
            for tagname in tqdm(out_data["packageNames"]):
                url = f"https://repo.packagist.org/p2/{tagname}.json";
                self.composerParser(tagname, url)

        else:
            urls = ["https://packagist.org/feeds/releases.rss", "https://packagist.org/feeds/packages.rss"]
            for url in urls:
                daily_items = []
                page = requests.get(url).text
                soup = BeautifulSoup(page, "html.parser")
                item_elements = soup.findAll("item")
                for item_tag in item_elements:
                    title_tag = item_tag.find("title")
                    daily_items.append(title_tag.text.split(" ")[0])

                with open("composer_daily_data.json", "w") as f:
                    json.dump(daily_items, f, indent=2)

                with open("composer_daily_data.json", "r") as f:
                    daily_data = json.load(f)

                for item in tqdm(daily_data):
                    url = f"https://repo.packagist.org/p2/{item}.json";
                    self.composerParser(item, url)
                

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scan', type=str,  help='enter scan yes/no')
    results = parser.parse_args()

    print(" [ OK ] Scan Started")
    res = composer_parser()
    res.startParsing(results.scan)
    print("Scan Complete")