#!/usr/bin/python

import time
import datetime
from time import sleep
import os
import sys
import re
from languageAdvisory.github_advisory_db import GHSAdvisory
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
        self.products = settings.get('feeds', 'languages')


    def run(self):
        for product in self.products.split(','):
            if product == "ghsa":
                res = GHSAdvisory()
                res.initialize(self.date_update)
                print("GHSA Advisory [ OK ]")

if __name__ == "__main__":
    res = monitor()
    print(res.run())

