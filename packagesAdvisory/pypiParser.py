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


class pypi_parser():
    def __init__(self):
        pass

    def pypiParser(self, url_name, url):
        try:
            response = urllib.request.urlopen(url)
            data = json.load(response)

            dirName = url_name
         
            with open("pypi/%s.json" % dirName, "w") as outfile:
                json.dump(data, outfile)
        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {url}")


    def startParsing(self, fullscan):
        if fullscan == "yes":
            if not os.path.exists('pypi_data.json'):
                url = "https://pypi.org/simple/"
                jsonData = []
                page = requests.get(url).text
                soup = BeautifulSoup(page, "html.parser")
                a_elements = soup.findAll("a")
                for a_tag in a_elements:
                    jsonData.append(a_tag.text)

                with open("pypi_data.json", "w") as f:
                    json.dump(jsonData, f, indent=4)

            with open("pypi_data.json", "r") as f:
                out_data = json.load(f)

            i = 0
            for tagname in tqdm(out_data):
                url = f"https://pypi.org/pypi/{tagname}/json";
                self.pypiParser(tagname, url)
        else:
            urls = ["https://pypi.org/rss/updates.xml", "https://pypi.org/rss/packages.xml"]
            for url in urls:
                daily_items = []
                page = requests.get(url).text
                soup = BeautifulSoup(page, "html.parser")
                item_elements = soup.findAll("item")
                for item_tag in item_elements:
                    title_tag = item_tag.find("title")
                    daily_items.append(title_tag.text.split(" ")[0])

                with open("pypi_daily_data.json", "w") as f:
                    json.dump(daily_items, f, indent=2)

                with open("pypi_daily_data.json", "r") as f:
                    daily_data = json.load(f)

                process_json = {}

                for item in tqdm(daily_data):
                    url = f"https://pypi.org/pypi/{item}/json";
                    self.pypiParser(item, url)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scan', type=str,  help='enter scan full/daily')
    results = parser.parse_args()

    print(" [ OK ] Scan Started")
    res = pypi_parser()
    res.startParsing(results.scan)
    print("Scan Complete")
   