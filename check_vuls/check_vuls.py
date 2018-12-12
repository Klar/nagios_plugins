#!/usr/bin/python
# -*- coding: utf-8 -*-
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
filepath = "/var/vuls/results/current"


class CVE():
    def __init__(self, filepath, filename):
        self.filepath = filepath + '/' if not filepath.endswith('s') else filepath
        self.filename = filename
        self.cvekeys = ["serverName", "scannedCves", "KnownCves", "UnknownCves", "IgnoredCves"]

        with open(self.filepath + self.filename, "r") as open_file:
            try:
                self.json_data = json.loads(open_file.read().replace('\m', '').replace('\r', '').replace('\n', ''))
                open_file.close()
            except Exception as error:
                print error

    def checkCVE(self):
        result_dict = {}
        # loops over the report json file, gets the values for servername key and val
        for key, val in self.json_data.items():
            # checks if val is the equivalent to the actual server name by checking if the key matches
            # checks if there any actual scans, if not it gets looped over
            if key == self.cvekeys[0] and self.json_data[self.cvekeys[1]]:
                # we make a link to all cves so that we can use a new variable, for more readable code
                all_cves = self.json_data[self.cvekeys[1]]
                # print all_cves
                # the final results dict gets crafted, with the name at the beginning
                result_dict[val] = {}
                result_dict[val]['os_type'] = self.json_data['family']
                all_cve_ids = self.json_data[self.cvekeys[1]].keys()
                # then the scanned cve dicts get into the next loop
                for cve_numbers in all_cve_ids:
                    # the dict for each sperate cve gets loaded
                    cve_dict = all_cves[cve_numbers]
                    cve_id = cve_dict["cveID"]
                    result_dict[val][cve_id] = {}
                    result_dict[val][cve_id]["Packages"] = {}

                    results = []
                    for any_int in range(0, len(cve_dict['confidences'])):
                        results.append(cve_dict['confidences'][any_int]['score'])
                    result_dict[val][cve_id]['score'] = results

                    packageinfo = dict()
                    for item in cve_dict['affectedPackages']:
                        packageinfo[item["name"]] = {}
                        packageinfo[item["name"]]["notFixedYet"] = item["notFixedYet"]
                        packageinfo[item["name"]]['newversion'] = self.json_data['packages'][item["name"]]['newVersion'] + self.json_data['packages'][item["name"]]['newRelease']
                        packageinfo[item["name"]]['version'] = self.json_data['packages'][item["name"]]['version'] + self.json_data['packages'][item["name"]]['release']
                    result_dict[val][cve_id]["Packages"] = packageinfo

                    contentinfo = dict()
                    if cve_dict['cveContents']:
                        for type_cve in cve_dict['cveContents'].keys():
                            contentinfo[type_cve] = {}
                            contentinfo[type_cve]['summary'] = cve_dict['cveContents'][type_cve]['summary']
                        result_dict[val][cve_id]["content"] = contentinfo
                    else:
                        result_dict[val][cve_id]["content"] = {None: {"summary":  None}}
            else:
                continue
        return result_dict


if __name__ == "__main__":
    for argvs in sys.argv:
        argvs_c += 1
        if argvs == "-w":
            warning = sys.argv[argvs_c].split(",")[0]
        elif argvs == "-c":
            critical = sys.argv[argvs_c].split(",")[0]

    try:
        for filename_u in os.listdir(filepath):

            if filename_u.endswith('.txt'):
                continue
            elif not filename_u.endswith('.json'):
                continue
            else:
                filename = filename_u

            cveinst = CVE(filepath, filename)
            server_dic = cveinst.checkCVE()
            # print server_dic

            for servername, info_dict in server_dic.items():
                output = []
                # remove servers without cve packages
                if len(info_dict) != 0:
                    updateable_packages = []
                    state += 1
                    os_type = info_dict['os_type']
                    # print "%s - %s:" % (servername, os_type)
                    output.append("%s - %s:\n" % (servername, os_type))
                    for CveId, val in info_dict.items():
                        if CveId != 'os_type':
                            # print " * %s - Score %s - summary:" % (CveId, val['score'])
                            output.append(" * %s - Score %s - summary:\n" % (CveId, val['score']))
                            new_package = False
                            for package, keys in val["Packages"].items():
                                if package not in updateable_packages:
                                    new_package = True
                                    # print "\t* %s\n\t\tInstalled Version:\t%s\n\t\tNewest Version:\t\t%s\n" % (package, keys['version'], keys['newversion'])
                                    output.append("\t* %s\n\t\tInstalled Version:\t%s\n\t\tNewest Version:\t\t%s\n" % (package, keys['version'], keys['newversion']))
                                    updateable_packages.append(package)
                            if not new_package:
                                output.remove(" * %s - Score %s - summary:\n" % (CveId, val['score']))
                            else:
                                # print "\n\n"
                                output.append("\n\n")

                            # for cves in all_cve_ids:
                            #     if result_dict[val][cves]:
                            #         if item in result_dict[val][cves]["Packages"].keys():
                            #             result_dict[val][cves]["Packages"][item]['additionalcve'].append(cves)
                            #     else:

                    package_list = ' '.join(updateable_packages)
                    if os_type == "ubuntu":
                        output.append("Execute commands on %s to fix:\nsudo apt install %s -y\n\n\n\n" % (servername, package_list))
                    elif os_type == "centos":
                        output.append("Execute commands on %s to fix:\nsudo yum install %s -y\n\n\n\n" % (servername, package_list))
                print "".join(output)

    except Exception as error:
        print error
        unknown = True
        output = str(traceback.format_exc())
        perfdata = ""

    if state >= int(critical):
        # print "CRITICAL"
        sys.exit(2)
    elif state >= int(warning):
        # print "WARNING"
        sys.exit(1)
    elif unknown:
        print "UKNOWN - please check script"
        sys.exit(3)
    else:
        # print "OK - %s" % output
        sys.exit(0)
