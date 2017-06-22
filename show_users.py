#!/usr/bin/python
import commands
import sys
import traceback
from netaddr import IPNetwork, IPAddress, IPRange, IPSet
from datetime import datetime, time

# Settings
filepath = "/home/nagios/libexec/"
tmppath = "%stmp/" % filepath
file_name = sys.argv[0].replace(filepath, "")
debug = False
delimiter = ","

helptext = "%s -w <warning> -c <critical> -wip <whitelist-ip> -bip <blacklist-ip> -wuser <whitelist-user> -buser <blacklist-user> -shour <start-hour> -ehour <end-hour>" % file_name

# Var
argvs_c = 0
warning = False
critical = False
unknown = False
perfdata = ""
output = ""

startHour = None
endHour = None
unusal_login_time = 0

whitelist_user = None
whitelist_usercount = 0

blacklist_user = None
blacklist_usercount = 0

whitelist_ips = None
whitelist_ipcount = 0

blacklist_ips = None
blacklist_ipcount = 0

crit = 3
warn = 2


def get_osinfo():
    usernames = None
    usercount = 0
    user_netstat_dic = {}
    usernames_unique = None
    netstat_ips = None

    usercount = commands.getoutput("who|wc -l").strip()
    usercount = int(usercount)

    if usercount > 0:
        usernames = commands.getoutput("who|grep -v \"^ *$\"|awk '{print $1}'|sort").strip().split("\n")
        usernames_unique = list(set(usernames))
    
        netstat_ips = []
        for username in usernames_unique:
            user_netstat = []

            netstats = commands.getoutput('sudo netstat -npW 2>/dev/null| grep :22 | grep %s' % username).split('\n')

            for netstat in netstats:
                ip_addr = netstat.strip().split()
                ip_addr = ip_addr[4].rsplit(':', 1)[0]

                user_netstat.append(netstat)
                netstat_ips.append((ip_addr))


            user_netstat_dic[username] = user_netstat

    return int(usercount), usernames, user_netstat_dic, usernames_unique, netstat_ips

def isNowInTimePeriod(startHour, endHour, nowHour):
    if startHour < endHour:
        return nowHour >= startHour and nowHour <= endHour
    else: #Over midnight
        return nowHour >= startHour or nowHour <= endHour

# argument management
if len(sys.argv) <= 1:
    print helptext
    sys.exit()
else:
    for argvs in sys.argv:
        argvs_c += 1
        if argvs == "-wip":
            whitelist_ips = sys.argv[argvs_c].split(',')
        if argvs == "-bip":
            blacklist_ips = sys.argv[argvs_c].split(',')
        if argvs == "-wuser":
            whitelist_user = sys.argv[argvs_c].split(',')
        if argvs == "-buser":
            blacklist_user = sys.argv[argvs_c].split(',')
        if argvs == "-shour":
            startHour = int(sys.argv[argvs_c])
        if argvs == "-ehour":
            endHour = int(sys.argv[argvs_c])
        if argvs == "-w":
            warn = int(sys.argv[argvs_c])
        if argvs == "-c":
            crit = int(sys.argv[argvs_c])

try:
    usercount, usernames, user_netstat_dic, usernames_unique, netstat_ips = get_osinfo()

    if usercount > 0:
        netstat_ips = list(set(netstat_ips))  # remove duplicate ips
    
        # day // night warning
        if startHour and endHour != None:
            nowHour = datetime.now().hour

            timeperiod = isNowInTimePeriod(startHour, endHour, nowHour)

            if timeperiod == True:
                output += "  * Unusual Login Time: %i:00 till %i:00 is blacklisted\n" % (startHour, endHour)
                crit = True
                unusal_login_time += 1

        # blacklisted IP
        blacklist_ip_set = IPSet()
        if blacklist_ips is not None:
            for netstat_ip in netstat_ips:
                for blacklist_ip in blacklist_ips:
                    blacklist_ip_set.add(blacklist_ip)
                
                if IPAddress(netstat_ip) in blacklist_ip_set:
                        output += "  * IP %s is blacklisted!\n" % netstat_ip
                        warn = True
                        blacklist_ipcount += 1

        # whitelist IP
        whitelist_ip_set = IPSet()
        if whitelist_ips is not None:
            for netstat_ip in netstat_ips:

                for whitelist_ip in whitelist_ips:
                    whitelist_ip_set.add(whitelist_ip)
                
                if IPAddress(netstat_ip) not in whitelist_ip_set:
                        output += "  * IP is not whitelisted! %s\n" % netstat_ip
                        warn = True
                        whitelist_ipcount += 1

        # blacklisted user
        if blacklist_user is not None:
            for user in blacklist_user:
                if user in usernames_unique:
                    output += "  * USER %s is blacklisted!\n" % user
                    warn = True
                    blacklist_usercount += 1
                
        # whitelisted user
        if whitelist_user is not None:
            for user in usernames_unique:
                if user not in whitelist_user:
                    output += "  * USER is not whitelisted! %s\n" % user
                    warn = True
                    whitelist_usercount += 1
            
        usernames_count = {i: usernames.count(i) for i in usernames}

        output += "\n[users: %(usernames_count)s]\n" % locals()

        for user in usernames_unique:
            output += "\n== %s ==" % user
            user_logintime = commands.getoutput('who | grep %s | awk \'{print $3 " "$4}\'' % user).strip().split("\n")
            output += "\n  login time:"
            for logintime in user_logintime:
                output += "\n     * " + logintime
            
            output += "\n  netstat output:"
            for netstat in user_netstat_dic[user]:
                if len(netstat):
                    output += "\n     * " + netstat

    blacklist_ipcount = whitelist_ipcount + blacklist_ipcount
    blacklist_usercount = whitelist_usercount + blacklist_usercount

    perfdata += "unusal_login_time=%d " % unusal_login_time
    perfdata += "blacklisted_ip=%d " % blacklist_ipcount
    perfdata += "blacklisted_user=%d " % blacklist_usercount
    perfdata += "user=%(usercount)s" % locals()

except:
    unknown = True
    output = str(traceback.format_exc())

if unknown:
    print "UKNOWN - output: %(output)s\nplease check script | %(perfdata)s" % locals()
    sys.exit(3)
elif usercount >= crit:
    print "CRITICAL\n%(output)s | %(perfdata)s" % locals()
    sys.exit(2)
elif usercount >= warn:
    print "WARNING\n%(output)s | %(perfdata)s" % locals()
    sys.exit(1)
else:
    print "OK %(output)s | %(perfdata)s" % locals()
    sys.exit(0)
