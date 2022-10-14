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
from packagesAdvisory.elixir_hex_advisory import elixir_hex_advisory
from packagesAdvisory.pub_dev_advisory import pub_dev_advisory
from packagesAdvisory.crates_io import crate_scan
from packagesAdvisory.ruby_packages import ruby_info
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
        for product in self.products.split(','):
            if product == "npm":
                res = npm_parser()
                res.startParsing('no')
                print("NPM Package Advisory [ OK ]")

            if product == "pypi":
                res = pypi_parser()
                res.startParsing('no')
                print("Pypi Package Advisory [ OK ]")

            if product == "composer":
                res = composer_parser()
                res.startParsing('no')
                print("Composer Package Advisory [ OK ]")

            if product == "debian":
                res = debianParser()
                res.intialize()
                print("Debian Package Advisory [ OK ]")

            if product == "ubuntu":
                res = ubuntuParser()
                res.intialize()
                print("Ubuntu Package Advisory [ OK ]")
            
            if product == "hex":
                res = elixir_hex_advisory()
                res.rssfeed()
                print("Hex Package Advisory [ OK ]")
            
            if product == "pub_dev":
                res = pub_dev_advisory()
                res.rssfeed()
                print("Pub.Dev Package Advisory [ OK ]")

            if product == "crate":
                res = crate_scan()
                res.rssfeed()
                print("Crate Package Advisory [ OK ]")

            if product == "rubygems":
                res = ruby_info()
                res.rssfeed()
                print("Rubygems Package Advisory [ OK ]")


if __name__ == "__main__":
    res = monitor()
    res.run()

