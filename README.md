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
