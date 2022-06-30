import time
import datetime
from time import sleep
import os
import sys
import re
from packagesAdvisory.npmParser import npm_parser
from packagesAdvisory.composerParser import composer_parser
from packagesAdvisory.pypiParser import pypi_parser
from packagesAdvisory.debianParser import debianParser
from packagesAdvisory.ubuntuParser import ubuntuParser

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
        self.products = settings.get('feeds', 'packagesAdvisory')


    def run(self):
        update_filename = "/var/DB/feeds/updated/%s_packages.json" % datetime.datetime.today().strftime('%Y-%m-%d').replace("-", "_")

        update_filename_path = Path(update_filename)
        if update_filename_path.is_file():
            with open(update_filename, "r") as f:
                updated_array = json.load(f)
        else:
            updated_array = {}

        for product in self.products.split(','):
            if product == "npm":
                res = npm_parser()
                updated_array['npm'] = res.startParsing('no')
                print("NPM Package Advisory [ OK ]")

            if product == "pypi":
                res = pypi_parser()
                updated_array['pypi'] = res.startParsing('no')
                print("Pypi Package Advisory [ OK ]")

            if product == "composer":
                res = composer_parser()
                updated_array['composer'] = res.startParsing('no')
                print("Composer Package Advisory [ OK ]")

            if product == "debian":
                res = debianParser()
                updated_array['debian'] = res.intialize()
                print("Debian Package Advisory [ OK ]")

            if product == "ubuntu":
                res = ubuntuParser()
                updated_array['ubuntu'] = res.intialize()
                print("Ubuntu Package Advisory [ OK ]")

        with open(update_filename, 'w') as outfile:
            json.dump(updated_array, outfile, indent=2)

if __name__ == "__main__":
    res = monitor()
    res.run()

