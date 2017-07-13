#!/usr/bin/python
import traceback
import json
import sys
import os

argvs_c=0
warning=1
critical=5
state=0
unknown=False
output=""
perfdata=""

for argvs in sys.argv:
    argvs_c += 1
    if argvs == "-w":
        warning = sys.argv[argvs_c].split(",")[0]
    elif argvs == "-c":
        critical = sys.argv[argvs_c].split(",")[0]

filepath = "/var/vuls/results/current/"

class CVE():
    def __init__(self, filepath, filename):
        self.filepath = filepath
        self.filename = filename
        self.cvekeys = ["ServerName", "ScannedCves", "KnownCves", "UnknownCves", "IgnoredCves"]


        with open(self.filepath + filename) as json_data:
            self.json_data = json.load(json_data)

    def checkCVE(self):
        result_dict = {}
        for key, val in self.json_data.items():
            if key == self.cvekeys[0] and self.json_data[self.cvekeys[1]] is not None:
                result_dict[val] = {}
                for pack in self.json_data[self.cvekeys[1]]:
                    # print pack
                    result_dict[self.json_data["ServerName"]][pack["CveID"]] = {}
                    packageinfo = {}

                    for item in pack['Packages']:
                        packageinfo[item["Name"]] = {}
                        packageinfo[item["Name"]]["Version"] = item["Version"]
                        packageinfo[item["Name"]]["NewVersion"] = item["NewVersion"]
                        result_dict[self.json_data["ServerName"]][pack["CveID"]]["Packages"] = packageinfo
                    if self.json_data[self.cvekeys[2]] is not None:
                        for kownCevs in self.json_data[self.cvekeys[2]]:
                            if "CveDetail" in kownCevs.keys():
                                if "CveID" in kownCevs['CveDetail'].keys():
                                    if kownCevs['CveDetail']["CveID"] == pack["CveID"]:
                                        result_dict[self.json_data["ServerName"]][pack["CveID"]]['Score'] = kownCevs['CveDetail']['Nvd']['Score']
                                    else:
                                        continue
                    if self.json_data[self.cvekeys[3]] is not None:
                        for unknownCves in self.json_data[self.cvekeys[3]]:
                            if "CveDetail" in unknownCves.keys():
                                if "CveID" in unknownCves['CveDetail'].keys():
                                    if unknownCves['CveDetail']["CveID"] == pack["CveID"]:
                                        result_dict[self.json_data["ServerName"]][pack["CveID"]]['Score'] = unknownCves['CveDetail']['Nvd']['Score']
                                    else:
                                        continue
                    if self.json_data[self.cvekeys[4]] is not None:
                        for ignoredCves in self.json_data[self.cvekeys[4]]:
                            if "CveDetail" in ignoredCves.keys():
                                if "CveID" in ignoredCves['CveDetail'].keys():
                                    if ignoredCves['CveDetail']["CveID"] == pack["CveID"]:
                                        result_dict[self.json_data["ServerName"]][pack["CveID"]]['Score'] = ignoredCves['CveDetail']['Nvd']['Score']
                                    else:
                                        continue
        return result_dict

try:
    for filename in os.listdir(filepath):

        if not filename.endswith('.json'):
            continue

        cveinst = CVE(filepath, filename)
        server_dic = cveinst.checkCVE()

        for servername, packages in server_dic.items():
            # remove servers without cve packages
            if len(packages) != 0:

                state += 1

                print "%s:" % servername


                for CveId, val in packages.items():
                    if not "Score" in val:
                        val["Score"] = " - "

                    print " * %s - Score: %s" % (CveId, val["Score"])

                    # print val["Packages"]
                    for package, keys in val["Packages"].items():
                        print "\t* %s \n\t\t* Current Version: \t%s\n\t\t* New Version:\t\t%s" % (package, keys["Version"], keys["NewVersion"])
                        #print "\t* %s " % (package)

                print "\n"

except:
    unknown = True
    output = str(traceback.format_exc())
    perfdata = ""

if state >= int(critical):
    #print "CRITICAL"
    sys.exit(2)
elif state >= int(warning):
    #print "WARNING"
    sys.exit(1)
elif unknown:
    print "UKNOWN - please check script"
    sys.exit(3)
else:
    #print "OK - %s" % output
    sys.exit(0)
