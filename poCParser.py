import time
import datetime
from time import sleep
import os
import sys
import re
from poCAdvisory.checkpoint import moniCheckpointDB
from poCAdvisory.emerginThreats import emerginThreats
from poCAdvisory.fortiguard import moniFortiguard
from poCAdvisory.nessus import moniNessusDB
from poCAdvisory.exploit_db import moniExploitDB
from poCAdvisory.packetstorm import moniPacketStromDB
from poCAdvisory.vuln_lab import moniVulnDB
from poCAdvisory.zdi_adv import moniZdiDB
from poCAdvisory.chromium import moniChromiumDB
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
        self.products = settings.get('feeds', 'poCAdvisory')


    def run(self):
        for product in self.products.split(','):
            if product == "chromium":
                res = moniChromiumDB()
                res.initialize(self.date_update)
                print("Chromium Advisory [ OK ]")

            if product == "exploit-db":
                res = moniExploitDB()
                res.initialize(self.date_update)
                print("Exploit-DB Advisory [ OK ]")

            if product == "packetstorm":
                res = moniPacketStromDB()
                res.initialize(self.date_update)
                print("PacketStorm Advisory [ OK ]")
        
            if product == "vuln-lab":
                res = moniVulnDB()
                res.initialize(self.date_update)
                print("Vuln-Lab Advisory [ OK ]")

            if product == "zdi":
                res = moniZdiDB()
                res.initialize(self.date_update)
                print("ZDI Advisory [ OK ]")

            if product == "checkpoint":
                res = moniCheckpointDB()
                res.initialize(self.date_update)
                print("Checkpoint Advisory [ OK ]")

            if product == "chromeBrowser":
                res = chromeBrowser()
                res.initialize(self.date_update)
                print("chromeBrowser Advisory [ OK ]")

            if product == "emerginThreats":
                res = emerginThreats()
                res.initialize(self.date_update)
                print("emerginThreats Advisory [ OK ]")

            if product == "fortiguard":
                res = moniFortiguard()
                res.initialize(self.date_update)
                print("Fortiguard Advisory [ OK ]")

            if product == "nessus":
                res = moniNessusDB()
                res.initialize(self.date_update)
                print("Nessus Advisory [ OK ]")


if __name__ == "__main__":
    res = monitor()
    res.run()

