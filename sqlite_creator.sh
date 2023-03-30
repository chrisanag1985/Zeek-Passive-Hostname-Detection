#!/bin/bash

# check first if exists the file
rm -f /var/db/passive_hosts.sqlite
# make it to create if not exists
sqlite3 /var/db/passive_hosts.sqlite "create table hostnames (mac text ,ip text primary key,hostname text);"
