# Zeek-Passive-Hostname-Detection
Detecting Hostnames and enrich Zeek logs based on DHCP protocol

## How it works.

It sees the dhcp requests/replies and extracts the hostname,mac address and ip.
Then it loads it to a Zeek table and use sqlite db for persistency.

It adds in the connection id (conn$id) 2 new fields that contains the hostname of the `orig_h` and `resp_h`. It does not add the
resolved hostname at the dhcp connections to avoid inserting false data.

It also add it to `Files::Info` and `X509::Info`, so you can see the hostname field in all the logs of Zeek.

## What will not do

It will not find hostnames of the machines with static ips.

## Installation


Load  the folder in your `local.zeek` and `zeekctl deploy`.


## Usage

After a while and when the clients of the network will start to request ips (maybe will take a day if they have already taken their ips), you will see to the Zeek logs the hostname.

The deletion of the record will occur only if the hostname and the mac address match. I don't delete only based on hostname because maybe some clients have the same default hostname.

Options:

You can change the const `redef Passive_Entities::entities_store_persistency` (default = Broker::MEMORY) in you want to save the entities in an sqlite for persistency. Legit values are `Broker::MEMORY` or `Broker::SQLITE`.


## TODO

- Maybe i will add an expiration timer for the records.
- Add more enrich information based on DHCP Options (like Router,ntp server,dns servers) #if they have internal ips.
- Test it on cluster mode with seperated nodes
- Move Event `entity_found` to Proxy or Master Nodes with Broker
- Test it and find bugs that maybe i missed.
- Write a better README.
