# Zeek-Passive-Hostname-Detection
Detecting Hostnames and enrich Zeek logs based on DHCP protocol 

## How it works.

It sees the dhcp requests/replies and extracts the hostname,mac address and ip.
Then it loads it to a Zeek table and also to a sqlite db for persistancy.

It adds in the connection id (conn$id) 2 new fields that contains the hostname of the `orig_h` and `resp_h`. It does not add the 
hostname resolving only in the dhcp connections to avoid inserting false data.

It also add it to `Files::Info` and `X509::Info`, so you can see the hostname field in all the logs of Zeek.

## What will not do

It will not find hostnames of the machines with static ips.

## Installation

Firstly you have to create an sqlite database.
You can do that by running the script that is provided in this repository (You have to install the `sqlite3 package`).

```
sh sqlite_creator.sh
```
This will create a table `hostnames` inside the `/var/db/passive_hosts.sqlite`.

Then you can `@load` the 4 scripts  on the `local.zeek` and you are done. 


## Usage

After a while and when the clients of the network will start to request ips (maybe will take a day if they have already taken their ips), you 
will see to the Zeek logs the hostname. Also if the client take another ip the Zeek script will go and update the Zeek table and the sqlite db.

The deletion of the record will occur only if the hostname and the mac address match. I don't delete only based on hostname because maybe some clients have the same default hostname.

## TODO

- Maybe i will add an expiration timer for the records.
- Add to read file with static ip assignments at `zeek_init()`.
- Add more enrich information based on DHCP Options (like Router,ntp server,dns servers) #if they have internal ips.
- Test it and find bugs that maybe i miss.
- Write a better README.
