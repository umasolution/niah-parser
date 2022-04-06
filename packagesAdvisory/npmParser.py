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

class npm_parser():
    def __init__(self):
        pass
    
    def npmParser(self, url_name, url):
        data = {}
        try:
            response = urllib.request.urlopen(url)
            data = json.load(response)

            if 'name' in data:
                name = data["name"]
            else:
                name = ""

            if 'dist-tags' in data:
                dist_tags = data["dist-tags"]
            else:
                dist_tags = ""

            if 'description' in data:
                description = data["description"]
            else:
                description = ""

            if 'author' in data:
                author = data["author"]
            else:
                author = []

            if 'license' in data:
                license = data["license"]
            else:
                license = []

            if 'readme' in data:
                readme = data["readme"]
            else:
                readme = ''

            i = 0
            results_json = {}
            results_json['versions'] = {}

            results_json['name'] = name
            results_json['dist-tags'] = dist_tags
            results_json['description'] = description
            results_json['author'] = author
            results_json['license'] = license
            results_json['readme'] = readme

            sorted_key_value = sorted(data["versions"], key=lambda k: k, reverse=True)
            for key_data in sorted_key_value:
                info = data["versions"][key_data]

                results_json['versions'][key_data] = {}

                if 'name' in info:
                    verName = info["name"]
                else:
                    verName = ""

                if 'version' in info:
                    version = info["version"]
                else:
                    version = ""

                if 'description' in info:
                    verDescription = info["description"]
                else:
                    verDescription = ""

                if 'license' in info:
                    verLicense = info["license"]
                else:
                    verLicense = []

                if 'author' in info:
                    verAuthor = info["author"]
                else:
                    verAuthor = []

                dependencies = []

                if 'dependencies' in info:
                    for k, v in info['dependencies'].items():
                        res = {}
                        res['package'] = k
                        res['version'] = v
                        dependencies.append(res)

                if '_nodeVersion' in info:
                    nodeVersion = info["_nodeVersion"]
                else:
                    nodeVersion = {}

                if '_npmVersion' in info:
                    npmVersion = info["_npmVersion"]
                else:
                    npmVersion = {}

                if 'dist' in info:
                    dist = info["dist"]
                else:
                    dist = {}

                results_json['versions'][key_data]["name"] = verName
                results_json['versions'][key_data]["version"] = version
                results_json['versions'][key_data]["description"] = verDescription
                results_json['versions'][key_data]["license"] = verLicense
                results_json['versions'][key_data]["author"] = verAuthor
                results_json['versions'][key_data]["dependencies"] = dependencies
                results_json['versions'][key_data]["nodeVersion"] = nodeVersion
                results_json['versions'][key_data]["npmVersion"] = npmVersion
                results_json['versions'][key_data]["dist"] = dist

            results_json['current'] = results_json['versions'][sorted_key_value[0]]
            
            if "/" in url_name:
                dirName = url_name.split("/")[0] + "_" + url_name.split("/")[1]
            else:
                dirName = url_name


            with open("/var/DB/packages/npm/%s.json" % dirName, "w") as outfile:
                json.dump(results_json, outfile)

        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {url}")
            print(data)


    def startParsing(self, fullscan):
        if fullscan == "yes":
            if not os.path.exists('npm_pkg.json'):
                url = "https://replicate.npmjs.com/_all_docs"
                os.system(f"wget {url}")
                os.system("mv _all_docs npm_pkg.json")
            with open("npm_pkg.json", "r") as f:
                out_data = json.load(f)

            i = 0
            for tagname in tqdm(out_data["rows"]):
                if tagname["id"].startswith("-"):
                    continue
                else:
                    url = f"https://registry.npmjs.org/{tagname['id']}";
                    self.npmParser(tagname["id"], url)

                i = i + 1
        else:
            url = "https://registry.npmjs.org/-/rss"
            daily_items = []
            page = requests.get(url).text
            soup = BeautifulSoup(page, "html.parser")
            item_elements = soup.findAll("item")
            for item_tag in item_elements:
                guid_tag = item_tag.find("guid")
                guid_list = guid_tag.text.split("/")
                if len(guid_list) == 5:
                    daily_items.append(guid_list[4])
                elif len(guid_list) == 6:
                    daily_items.append(guid_list[4] + "/" + guid_list[5])

            with open("npm_daily_data.json", "w") as f:
                json.dump(daily_items, f, indent=2)

            with open("npm_daily_data.json", "r") as f:
                daily_data = json.load(f)

            for item in tqdm(daily_data):
                url = f"https://registry.npmjs.org/{item}";
                self.npmParser(item, url)
               


if __name__ == '__main__':
    #if i > 1128772:
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scan', type=str,  help='enter scan yes/no')
    results = parser.parse_args()

    print(" [ OK ] Scan Started")
    res = npm_parser()
    res.startParsing(results.scan)
    print("Scan Complete")


