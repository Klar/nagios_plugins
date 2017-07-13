#!/usr/bin/python
import commands
import sys
import traceback
from netaddr import IPAddress, IPSet
from datetime import datetime, time
import re

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

whitelist_user = []
whitelist_usercount = 0

blacklist_user = []
blacklist_usercount = 0

whitelist_ips = []
whitelist_ipcount = 0

blacklist_ips = []
blacklist_ipcount = 0

logged_inas_root_count = 0
logged_inas_other_count = 0
logged_inas_tty_count = 0

crit = 3
warn = 2

def create_userdic():
    """ creates a userdict from 'who' information, loops them over netstat (ips) and returns them all in a dict"""
    usernames = None
    users = dict()
    usercount = 0
    user_netstat_dic = dict()
    usernames_unique = []
    netstat_ips = None

    usercount = commands.getoutput("who|wc -l").strip()
    usercount = int(usercount)

    if usercount:
        usernames = commands.getoutput("who|grep -v \"^ *$\"|awk '{print $1,$2,$3,$4}'|sort").strip().split("\n")
        for userwho in usernames:
            username, con_type, login_date, login_time = userwho.split(' ')

            login_datetime = "%(login_date)s %(login_time)s" % locals()

            if username not in users.keys():
                users[username] = dict(
                        con_types=[],
                        login_datetime=[],
                        netstat_line=[],
                        netstat_ips=[]
                )
            users[username]['con_types'].append(con_type)
            
            users[username]['login_datetime'].append(login_datetime)

        netstat_ips = []
        for username in users.keys():
            netstats = commands.getoutput('sudo netstat -npW 2>/dev/null| grep :22 | grep %(username)s' % locals()).split('\n')
            for netstat in netstats:
                if len(netstat) > 0:
                    ip_addr = netstat.strip().split()[4].rsplit(':', 1)[0]
                    users[username]['netstat_line'].append(netstat)
                    users[username]['netstat_ips'].append((ip_addr))

    return users, usercount

def isNowInTimePeriod(startHour, endHour, nowHour):
    """ input startHour + endHour and you will see if you are currently in between """
    if startHour < endHour:
        return nowHour >= startHour and nowHour <= endHour
    else: #Over midnight
        return nowHour >= startHour or nowHour <= endHour

def isrootloggedin():
    """check if a user 'updated' his rights to another user or even root, dict with username and tty"""
    logged_inas = list()
    su_auxs = commands.getoutput('ps aux | grep -w "[s]u"').split('\n')
    if len(su_auxs) > 1:
        tmp_tty = list()
        for su_aux in su_auxs:
            logged_userlist = list()

            su_aux = re.sub('\ +', ' ', su_aux)
            su_aux = su_aux.strip().split(' ')

            if "sudo" not in su_aux and su_aux[6] in tmp_tty:
                continue

            if len(su_aux) == 13: #su to another user
                logged_userlist.append(su_aux[12]) #username
                logged_userlist.append(su_aux[6]) #tty
            else: #root logged in
                logged_userlist.append(su_aux[0]) #username
                logged_userlist.append(su_aux[6]) #tty

            tmp_tty.append(su_aux[6])
            
            logged_inas.append(logged_userlist)

    return logged_inas

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
    users, usercount = create_userdic()

    if len(users) > 0:
        timeperiod_output = ""

        usernames_count = {user: len(users[user]['login_datetime']) for user in users.keys()}
        print "[users: %(usernames_count)s]\n" % locals()
    
        # day // night warning
        if startHour and endHour:
            nowHour = datetime.now().hour
            now_Day = datetime.now().weekday()

            timeperiod = isNowInTimePeriod(startHour, endHour, nowHour)

            if timeperiod or now_Day == 5 or now_Day == 6:
                timeperiod_output = "  * Unusual Login Time: %(startHour)i:00 till %(endHour)i:00 and Saturday // Sunday is blacklisted\n" % locals()
                print timeperiod_output
                critical = True
                unusal_login_time += 1
        
        # get root ttys
        root_ttys = isrootloggedin()

        for username in users.keys():
            logintime_output = ""
            netstat_output = ""
            blacklist_ip_output = ""
            whitelist_ip_output = ""
            blacklist_user_output = ""
            whitelist_user_output = ""
            logged_inas = ""
            logged_inas_tty = ""

            for netstat_ip in users[username]["netstat_ips"]:
                if netstat_ip in blacklist_ips:
                    critical = True
                    blacklist_ip_output = "  * IP %(netstat_ip)s is blacklisted!\n" % locals()
                    blacklist_ipcount += 1

                if whitelist_ips:
                    whitelist_ip_set = IPSet()
                    for whitelist_ip in whitelist_ips:
                        whitelist_ip_set.add(whitelist_ip)
                    
                    if IPAddress(netstat_ip) not in whitelist_ip_set:
                    # if netstat_ip not in whitelist_ips:
                        critical = True
                        whitelist_ip_output = "  * IP %(netstat_ip)s is not whitelisted!\n" % locals()
                        whitelist_ipcount += 1

            if username in blacklist_user:
                blacklist_user_output = "  * USER %(username)s is blacklisted!\n" % locals()
                critical = True
                blacklist_usercount += 1

            if whitelist_user:
                if username not in whitelist_user:
                    whitelist_user_output = "  * user %(username)s is not whitelisted!\n" % locals()
                    critical = True
                    whitelist_usercount += 1

            logintime_output += str(users[username]["login_datetime"])
            
            # logged in as root
            for user_tty in root_ttys:
                tty_username = user_tty[0]
                logged_tty = user_tty[1]

                if logged_tty in users[username]["con_types"]:
                    logged_inas += "  * %(username)s logged in as %(tty_username)s!\n" % locals()
                    if tty_username == "root":
                        logged_inas_root_count += 1
                        critical = True
                    else:
                        logged_inas_other_count += 1
                        warning = True

            # logged in from (tty) esx
            if any("tty" in con_type for con_type in users[username]["con_types"]):
                logged_inas_tty = "  * %(username)s logged in from esx like tty!\n" % locals()
                logged_inas_tty_count += 1
                warning = True

            for netstat_line in users[username]['netstat_line']:
                netstat_output += "  * %(netstat_line)s\n" % locals()

            con_types = users[username]['con_types']
            print "user: %(username)s%(con_types)s\nlogintime: %(logintime_output)s\n%(netstat_output)s" % locals()
            print "%(logged_inas_tty)s%(logged_inas)s%(blacklist_user_output)s%(whitelist_user_output)s%(blacklist_ip_output)s%(whitelist_ip_output)s" % locals()

        # user logged in
        if usercount >= warn:
            warning = True
        if usercount >= crit:
            critical = True

    blacklist_ipcount = whitelist_ipcount + blacklist_ipcount
    blacklist_usercount = whitelist_usercount + blacklist_usercount

    perfdata += "unusal_login_time=%(unusal_login_time)d" % locals()
    perfdata += " blacklisted_ip=%(blacklist_ipcount)d" % locals()
    perfdata += " blacklisted_user=%(blacklist_usercount)d" % locals()
    perfdata += " user=%(usercount)d" % locals()
    perfdata += " logged_inas_root=%(logged_inas_root_count)d" % locals()
    perfdata += " logged_inas_other=%(logged_inas_other_count)d" % locals()
    perfdata += " logged_inas_tty=%(logged_inas_tty_count)d" % locals()

except:
    unknown = True
    output = str(traceback.format_exc())

if unknown:
    print "UKNOWN - output: %(output)s\nplease check script | %(perfdata)s" % locals()
    sys.exit(3)
elif critical:
    print "| %(perfdata)s" % locals()
    sys.exit(2)
elif warning:
    print "| %(perfdata)s" % locals()
    sys.exit(1)
else:
    print "| %(perfdata)s" % locals()
    sys.exit(0)