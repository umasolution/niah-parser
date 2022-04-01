from bs4 import BeautifulSoup
from lxml import html
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


jsonData = {}
init = 1


def get_licence(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, "html.parser")

    if soup.findAll('span', {'class': 'color-fg-default text-bold mr-1'}):
        language = soup.findAll('span', {'class': 'color-fg-default text-bold mr-1'})[0].text
        return language
    else:
        return False

def singleLink(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, "html.parser")

    elements = soup.find_all("div", class_="color-fg-muted pt-2")

    cveID = elements[0].text.strip()
    ghsaID = elements[1].text
    cves = {}
    ref = []
    vendor = ""
    product = ""
    g_url = ""
    elements = soup.find("div", class_="markdown-body comment-body p-0")

    if elements.find("p").text:
        description = elements.find("p").text
    else:
        description = "Description not available"
    total_links = len(elements.find_all("a"))

    for t in range(0, total_links):
        ref.append(elements.find_all("a")[t]["href"])
        if re.findall(r'https:\/\/github\.com\/(.*?)\/(.*?)\/', str(elements.find_all("a")[t]["href"])):
            git_data = re.findall(r'https:\/\/github\.com\/(.*?)\/(.*?)\/', str(elements.find_all("a")[t]["href"]))
            vendor = git_data[0][0]
            product = git_data[0][1]
            g_url = "https://github.com/%s/%s" % (vendor, product)
            
    cves["cveID"] = cveID
    cves["ghsaID"] = ghsaID
    cves["description"] = description
    cves["references"] = ref
    cves["vendor"] = vendor
    cves["product"] = product
    cves["g_url"] = g_url

    return cves


results_git = []
results_nogit = []
results_git_license = [] 

def startParsing(url):
    while True:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, "html.parser")
        a_elements = soup.find_all("div", class_="lh-condensed flex-auto")

        links = []

        for a in a_elements:
            links.append("https://github.com" + a.find("a")["href"])

        for li in tqdm(links):
            res = singleLink(li)
            if res['g_url']:
                license = get_licence(url)
                if license:
                    res['license'] = license
                    results_git_license.append(res)
                else:
                    results_git.append(res)
            else:
                results_nogit.append(res)

        if soup.find("a", rel="next"):
            n = soup.find("a", rel="next")
            url = "https://github.com" + n["href"]
        else:
            break
    
    with open("unreviewed_data_git.json", "w") as f:
        json.dump(results_git, f, indent=4)
    
    with open("unreviewed_data_git_license.json", "w") as f:
        json.dump(results_git_license, f, indent=4)

    with open("unreviewed_data_nogit.json", "w") as f:
        json.dump(results_nogit, f, indent=4)



if __name__ == '__main__':
    print(" [ OK ] Scan Started")
    startParsing("https://github.com/advisories?query=type%3Aunreviewed")
    print("Scan Complete")
