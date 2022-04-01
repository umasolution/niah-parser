#!/usr/bin/python

import time
import datetime
from time import sleep
import os
import sys
import re
from nvd_parser.nvdParser import nvdGet
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
               	res = nvdGet(self.date_update)
                print("NVD Advisory [ OK ]")

if __name__ == "__main__":
    res = monitor()
    print(res.run())

