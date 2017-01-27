#!/bin/sh

#update cve database
go-cve-dictionary fetchjvn -latest -dbpath=/home/nagios/vuls/go-cve-dictionary/cve.sqlite3

#scan servers for current installed packages
vuls scan -config=/home/nagios/vuls/config.toml -results-dir=/home/nagios/vuls/results -cachedb-path=/home/nagios/vuls/cache.db

#generates report and sends it via E-Mail (cronjob in nagios user)
/bin/vuls report -config=/home/nagios/vuls/config.toml -cvedb-path=/home/nagios/vuls/go-cve-dictionary/cve.sqlite3 -results-dir=/home/nagios/vuls/results/ -format-one-line-text -format-full-text