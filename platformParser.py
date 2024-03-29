import time
import datetime
from time import sleep
import os
import sys
import re
from platformAdvisory.ubuntu_adv import moniUbuntuDB
from platformAdvisory.debian_adv import moniDebianDB
from platformAdvisory.redhat_adv import moniRedhatDB
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
        self.products = settings.get('feeds', 'platformAdvisory')


    def run(self):
        for product in self.products.split(','):
            if product == "debian":
                res = moniDebianDB()
                res.initialize(self.date_update)
                print("Debian Advisory [ OK ]")

            if product == "ubuntu":
                res = moniUbuntuDB()
                res.getrss(self.date_update)
                print("Ubuntu Advisory [ OK ]")
            
            if product == "redhat":
                res = moniRedhatDB()
                res.getrss(self.date_update)
                print("Redhat Advisory [ OK ]")

if __name__ == "__main__":
    res = monitor()
    res.run()

