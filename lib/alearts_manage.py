import json
import re
import sys
import os
import configparser
import psycopg2
import ast

class check_alerts():
    def __init__(self):
        self.settings = configparser.ConfigParser()
        self.settings.read('config.ini')
        self.hostName = self.settings.get('database', 'host')
        self.userName = self.settings.get('database', 'user')
        self.password = self.settings.get('database', 'pass')
        self.databaseName = self.settings.get('database', 'dbname')

        self.connection = psycopg2.connect(user=self.userName, password=self.password, host=self.hostName, port="5432", database=self.databaseName)
        self.cursor = self.connection.cursor()


    def update_alerts(self, alerts_type, alert_name, last_update, message):
        query = "select messages from alerttabs where alert_type='%s' and alert_name='%s'" % (alerts_type, alert_name)
        self.cursor.execute(query)
        fetchData = self.cursor.fetchall()

        if len(fetchData) > 0:
            messages = fetchData[0][0]
            if messages:
                messages = ast.literal_eval(messages)
            else:
                messages = []

            res = {}
            res['lastupdate'] = last_update
            res['message'] = message

            messages.append(res)

            query = "update alerttabs set messages='%s', last_update='%s' where alert_type='%s' and alert_name='%s'" % (json.dumps(messages), last_update, alerts_type, alert_name)
            print(query)
            self.cursor.execute(query)
            self.connection.commit()

