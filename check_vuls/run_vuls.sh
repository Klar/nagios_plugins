#!/bin/sh

#update cve database
go-cve-dictionary fetchjvn -latest -dbpath=/var/vuls/cve/cve.sqlite3 >/dev/null 2>&1
go-cve-dictionary fetchnvd -latest -dbpath=/var/vuls/cve/cve.sqlite3 >/dev/null 2>&1

#scan servers for current installed packages
vuls scan -config=/var/vuls/config.toml -results-dir=/var/vuls/results -cachedb-path=/var/vuls/cache/cache.db >/dev/null 2>&1
vuls report -config=/var/vuls/config.toml -results-dir=/var/vuls/results -cvedb-sqlite3-path /var/vuls/cve/cve.sqlite3 >/dev/null 2>&1
