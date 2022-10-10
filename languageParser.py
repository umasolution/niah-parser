#!/usr/bin/python

import time
import datetime
from time import sleep
import os
import sys
import re
from languageAdvisory.github_advisory import GHSAdvisory
from time import gmtime, strftime
import configparser
import logging
import os
import sys
import json
from pathlib import Path


class monitor():
    def __init__(self):
        now = datetime.datetime.now()
        self.date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
        settings = configparser.ConfigParser()
        settings.read('config.ini')
        self.products = settings.get('feeds', 'languages')


    def run(self):
        update_filename = "/var/DB/feeds/updated/%s.json" % datetime.datetime.today().strftime('%Y-%m-%d').replace("-", "_")

        update_filename_path = Path(update_filename)
        if update_filename_path.is_file():
            with open(update_filename, "r") as f:
                updated_cves = json.load(f)
        else:
            updated_cves = {}
            updated_cves['product_ids'] = []
            updated_cves['niah_ids'] = []

        for product in self.products.split(','):
            if product == "ghsa":
                res = GHSAdvisory()
                updated_cves = res.initialize(self.date_update, updated_cves)
                print("GHSA Advisory [ OK ]")

        with open(update_filename, 'w') as outfile:
            json.dump(updated_cves, outfile, indent=2)

if __name__ == "__main__":
    res = monitor()
    print(res.run())

