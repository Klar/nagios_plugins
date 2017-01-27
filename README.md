# nagios_plugins

## check_vuls.py 

Nagios Script for https://github.com/future-architect/vuls

How does it (currently) work?
- run 'run_vuls.sh' daily via cronjob
- run a icinga job for a daily check of 'check_vuls.py'
- get notified via icingaweb2 / icinga alert if host need updates