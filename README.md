# Zeek-Passive-Hostname-Detection
Detecting Hostnames and enrich Zeek logs based on DHCP protocol 

## How it works.

It sees the dhcp requests/replies and extracts the hostname,mac address and ip.
Then it loads it to a Zeek table and also to a sqlite db for persistancy.

## Installation

Firstly you have to create an sqlite database.
You can to that by running the script that is provided in this repository (You have to already install the `sqlite3 package`).

```
sh sqlite_creator.sh
```
This will create a table `hostnames` inside the `/var/db/passive_hosts.sqlite`.

Then you can `@load` the 2 scripts on the `local.zeek` and you are done. 

