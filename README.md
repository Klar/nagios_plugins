# nagios_plugins

## check_vuls.py 

Nagios Script for https://github.com/future-architect/vuls

### howto
How does it (currently) work?
- **run_vuls.sh** daily via cronjob

```
#run vuls daily mo-fr, generate python scripts, nagios will do a daily json parse
15 07 * * 1-5 /var/vuls/run_vuls.sh

#weekly mail for checking if vuls is working
45 07 * * 2 /var/vuls/weekly_vuls_mail.sh
```

- run an icinga job for a daily check of **check_vuls.py**
- get notified via icingaweb2 / icinga alert if host need updates

```
################################################
## Vulnerability check ON icinga2             ##
################################################

apply Service "check_vulnerability_hosts" {
        check_command = "check_by_ssh"
        check_interval = 24h
        retry_interval = 12h
        #vars.sla = ["mail-only"]
        vars.group = host.vars.group
        vars.scriptname = "check_vuls_hosts.py"
        vars.args = "-w 1 -c 2"

        assign where host.name == "icingahostname"
}
```

### todo
- add nagios config to github
- run vuls to scan more than once? otherwise we have to wait 24h to get the alert gone

## show_users.py 

 /home/nagios/libexec/show_users.py 
 show_users.py -w <warning> -c <critical> -wip <whitelist-ip> -bip <blacklist-ip> -wuser <whitelist-user> -buser <blacklist-user> -shour <start-hour> -ehour <end-hour>

* warning == warning if more than x logged in
* critical == critical if more than x logged in
* whitelist ip - all ips except this one will throw a warning
* blacklist ip - if logged in whith set IP(s), it will throw a warning
* whitelist user - same as above but for user(s) (whitelist ip)
* blacklist user - same as above but for users(s) (blacklist ip)
* start hour = no user should be logged in after start hour x otherwise it will go into critical state
* end hour = after hour x you will be able to login again without going into critical state


### howto

### icinga
```
template Host "ubuntu1604"
	...
	settings...
	...
}

apply Service "users" {
        check_command = "check_by_ssh_sudo"
        #vars.sla = ["empty"]
        vars.group = host.vars.group
        vars.scriptname = "show_users.py"
	vars.args = "-w 4 -c 6"
        assign where "ubuntu1604" in host.templates
        ignore where !host.address
}
```
