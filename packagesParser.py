import time
import datetime
from time import sleep
import os
import sys
import re
from packagesAdvisory.npmParser import npm_parser
from packagesAdvisory.composerParser import composer_parser
from packagesAdvisory.pypiParser import pypi_parser
from time import gmtime, strftime
import configparser
import logging
import os
import sys


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


if __name__ == "__main__":
    res = monitor()
    res.run()

