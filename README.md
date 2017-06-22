# nagios_plugins

## check_vuls.py 

Nagios Script for https://github.com/future-architect/vuls

### howto
How does it (currently) work?
- **run_vuls.sh** daily via cronjob
- run an icinga job for a daily check of **check_vuls.py**
- get notified via icingaweb2 / icinga alert if host need updates

### todo
- add nagios config to github
- run vuls to scan more than once? otherwise we have to wait 24h to get the alert gone

## show_users.py 

 /home/nagios/libexec/show_users.py 
 show_users.py -w <warning> -c <critical> -wip <whitelist-ip> -bip <blacklist-ip> -wuser <whitelist-user> -buser <blacklist-user> -shour <start-hour> -ehour <end-hour>

* warning == x  warning if more than x logged in 
* critical == x  critical if more than x logged in 
* whitelist ip - all ips except this one will throw a warning
* blacklist ip - if logged in whith this IP, it will throw a warning
* whitelist user - same as above (whitelist ip)
* blacklist user - same as above (blacklist ip)
* start hour = no user should be logged in after x otherwise it will go into critical state
* end hour = after this hour you will be able to login without going into critical state



### howto

### icinga
<code>
apply Service "users" {
        check_command = "check_by_ssh_sudo"
        #vars.sla = ["empty"]
        vars.group = host.vars.group
        vars.scriptname = "show_users.py"
        vars.args = host.vars.service_users_args
        assign where "ubuntu1604" in host.templates
        ignore where !host.address
}
</code>
