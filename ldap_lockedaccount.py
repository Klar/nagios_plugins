#!/usr/bin/python
import sys
import traceback
import commands

# Var
warning = False
critical = False
unknown = False
perfdata = ""
output = ""
filepath = "/home/nagios/libexec/"
argvs_c = 0
file_name = sys.argv[0].replace(filepath, "")
helptext = "%s -h <hostname-or-ip> -p <port> -w <warning> -c <critical> -b <dc=example,dc=me>" % file_name
warn = 1
criti = 2

user_block_count = 0

# argument management
if len(sys.argv) <= 1:
    print helptext
    sys.exit()
else:
    for argvs in sys.argv:
        argvs_c += 1
        if argvs == "-h":
            servername = sys.argv[argvs_c]
        if argvs == "-p":
            port = int(sys.argv[argvs_c])
        if argvs == "-b":
            domain = sys.argv[argvs_c]
        if argvs == "-w":
            warn = int(sys.argv[argvs_c])
        if argvs == "-c":
            crit = int(sys.argv[argvs_c])

try:
    is_locked = commands.getoutput('ldapsearch -h %(servername)s -p %(port)d -x -b %(domain)s -LLL "(&(objectclass=posixaccount)(pwdaccountlockedtime=*))" dn pwdAccountLockedTime' % locals()).strip()
    
    if is_locked:
        is_locked = is_locked.split("\n")
        print "LDAP user blocked"
        #remove empty values from list
        is_locked = filter(None, is_locked)

        for user_line in is_locked:
            if user_line.startswith("pwdAccountLockedTime"):
                print "  ==>  " + user_line + "\n"
            else:
                print "  * " + user_line
                user_block_count += 1

        if len(is_locked) > warn:
            warning = True
        elif len(is_locked) > crit:
            critical = True


    perfdata += "user_block_count=%(user_block_count)d" % locals()

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