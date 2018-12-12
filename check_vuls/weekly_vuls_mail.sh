#!/bin/sh

#update cve database
go-cve-dictionary fetchjvn -latest -dbpath=/var/vuls/cve/cve.sqlite3 > /var/vuls/weekly.txt
go-cve-dictionary fetchnvd -latest -dbpath=/var/vuls/cve/cve.sqlite3 >> /var/vuls/weekly.txt

#scan servers for current installed packages
vuls scan -config=/var/vuls/config.toml -results-dir=/var/vuls/results -cachedb-path=/var/vuls/cache/cache.db >> /var/vuls/weekly.txt

cat /var/vuls/weekly.txt | mail -s "Weekly Vuls Report" <mytomail@address.com> -aFROM:<myfrommail@address.com>
