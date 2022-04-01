import time
import datetime
from time import sleep
import os
import sys
import re
from poCAdvisory.gitPoC import git_sync
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
        self.others = settings.get('feeds', 'other')

    def run(self):
        date_update = self.date_update
        for product in self.others.split(','):
            if product == "gitpoc":
                print("GitHub PoC Sync Started.. [ OK ]")
                res = git_sync()
                res.gitSearch(date_update)
                print("GitHub PoC Sync Completed.. [ OK ]")

if __name__ == "__main__":
    res = monitor()
    res.run()
