import json
import requests
import os


class crate_scan():
    def _init_(self):
        pass

    def get_package(self, packagename):
        response = requests.get('https://crates.io/api/v1/crates/%s' % packagename)
        jsondata  = response.json()

        with open("/var/DB/packages/crates/%s.json" % packagename, "w") as outfile:
                json.dump(jsondata, outfile, indent=2)

        print("%s.json file created completely.....!!!!!! " %packagename)

    
    def rssfeed(self):
        print("RSS Feed started")
        response = requests.get('https://crates.io/api/v1/summary')
        jsondata  = response.json()
        
        just_updated = jsondata['just_updated']
        new_crates = jsondata['new_crates']

        for updated in just_updated:
            packagename = updated['name']
            print(packagename)
            self.get_package(packagename)

        for new in new_crates:
            packagename = new['name']
            print(packagename)
            self.get_package(packagename)

    def scan(self):
        i = 1
        while True:
            params = {
                'page': '%s' % i,
            }

            response = requests.get('https://crates.io/api/v1/crates', params=params)
            jsondata  = response.json()
            
            for data in jsondata['crates']:
                packagename = data['name']
                print(packagename)
                self.get_package(packagename)	
                
            i = i + 1
        
            if i == 1884:
                break   

if __name__ == "__main__":
    res = crate_scan()
    res.scan()