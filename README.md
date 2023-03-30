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

Then you can `@load` the 2 scripts (passive-host-learning.zeek and hostname-enrichemnt.zeek) on the `local.zeek` and you are done. 

`Disclaimer`: I don't include all the log files to the `hostname-enrichment.zeek`, but to can see how i am doing it and extend it by yourself.

## Usage

After a while and when the clients of the network will start to request ips (maybe will take a day if the have already taken their ips), you 
will see to the Zeek logs the hostname. Also if the client take another ip the Zeek script will go and update the Zeek table and the sqlite db.

The deletion of the record will occur only if the hostname and the mac address match. I don't delete only based on hostname because maybe some clients have the same default hostname.

## TODO

- Maybe i will add an expiration timer for the records.
- Test it and find bugs that maybe i miss.
- Write a better README.
