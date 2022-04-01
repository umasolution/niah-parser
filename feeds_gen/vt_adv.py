import sys
import configparser
import re
import os
import datetime
import json
import psycopg2

__all__ = ["getstatusoutput","getoutput","getstatus"]

def getstatus(file):
    """Return output of "ls -ld <file>" in a string."""
    import warnings
    warnings.warn("commands.getstatus() is deprecated", DeprecationWarning, 2)
    return getoutput('ls -ld' + mkarg(file))

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

def mk2arg(head, x):
    import os
    return mkarg(os.path.join(head, x))

def mkarg(x):
    if '\'' not in x:
        return ' \'' + x + '\''
    s = ' "'
    for c in x:
        if c in '\\$"`':
            s = s + '\\'
        s = s + c
    s = s + '"'
    return s


class moniVTDB():
    def __init__(self):
        self.daily = True
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        hostName = self.settings.get('database', 'host')
        userName = self.settings.get('database', 'user')
        password = self.settings.get('database', 'pass')
        databaseName = self.settings.get('database', 'dbname')
        self.connection = psycopg2.connect(user=userName,password=password,host=hostName,port="5432",database=databaseName)
        self.cursor = self.connection.cursor()   
        sys.setrecursionlimit(100000)

    def initialize(self, cve_id, scan=True):
        vtArray = []
        now = datetime.datetime.now()
        date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
        query = 'SELECT * FROM pocreference_db where cve_id="%s" and application="virustotal"' % cve_id
        self.cursor.execute(query)
        vtdb = self.cursor.fetchall();
        if len(vtdb) == 0 or scan == True:
            cmd = "python lib/vt_intelligence_downloader.py -n 2 'tag:%s' --cve %s" % (cve_id, cve_id)
            status, output = getstatusoutput(cmd)
            if status == 0:
                sample_hash = re.findall(r'INFO\s+(.*) download was successful', str(output))
                if len(sample_hash) != 0:
                    for sample in sample_hash:
                        reference = 'https://www.virustotal.com/gui/file/%s/detection' % sample
                        name = ''
                        details = {}
                        pub_date = ''
                        cmd = """INSERT INTO pocreference_db("application", "app_id", "cve_id", "description", "vuln_name", "details", "publish_date", "reference", "last_update")VALUES ('{application}', '{id}', '{cve}', '{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}')ON CONFLICT("cve_id", "app_id", "application")DO UPDATE SET ("description", "vuln_name", "details", "publish_date", "reference", "last_update") = ('{name}', '{name}', '{details}', '{pub_date}', '{url}', '{date_update}');""".format(id=sample, cve=cve_id, name=name, details=json.dumps(details), pub_date=pub_date, url=reference, date_update=date_update, application='virustotal')
                        print(cmd)
                        self.cursor.execute(cmd)
                        self.connection.commit() 


                

if __name__ == "__main__":
        res = moniVTDB()
        res.initialize('CVE-2012-0158', scan=True)



