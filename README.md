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

The deletion of the record will occur only if the mac address match. I don't delete only based on hostname because maybe some clients have the same default hostname.

Options:

You can change the const `Passive_Entities::entities_store_persistency` (default = Broker::MEMORY) in you want to save the entities in an sqlite for persistency. Legit values are `Broker::MEMORY` or `Broker::SQLITE`


## Sample `conn.log`

```
{"ts":1361916444.804841,"uid":"CDmVGN1I7eEE85gwY4","id.orig_h":"172.16.133.40","id.orig_p":50297,"id.resp_h":"96.43.146.48","id.resp_p":443,"id.orig_hostname":"JDT096","proto":"tcp","service":"ssl","duration":3.39282488822937,"orig_bytes":1850,"resp_bytes":3079,"conn_state":"S1","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADda","orig_pkts":12,"orig_ip_bytes":2342,"resp_pkts":9,"resp_ip_bytes":3451,"orig_l2_addr":"00:21:70:63:41:15","resp_l2_addr":"00:90:7f:3e:02:d0","community_id":"1:k2/On2MP068bpCHYtdVbqaxPjhA=","resp_geo.country_code":"US","resp_geo.latitude":37.751,"resp_geo.longitude":-97.822,"resp_asn.number":14340,"resp_asn.organization":"SALESFORCE"}
{"ts":1361916448.480786,"uid":"CBrZGC3h8QUak9swLa","id.orig_h":"172.16.133.34","id.orig_p":50719,"id.resp_h":"96.43.146.176","id.resp_p":443,"id.orig_hostname":"JDT168[jaalam.net]","proto":"tcp","service":"ssl","duration":3.4028120040893555,"orig_bytes":8381,"resp_bytes":12825,"conn_state":"S1","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"ShADda","orig_pkts":19,"orig_ip_bytes":9153,"resp_pkts":20,"resp_ip_bytes":13637,"orig_l2_addr":"9c:8e:99:f3:8c:19","resp_l2_addr":"00:90:7f:3e:02:d0","community_id":"1:NRZMq/TxorOMcAZBa0OKyRs8cgc=","resp_geo.country_code":"US","resp_geo.latitude":37.751,"resp_geo.longitude":-97.822,"resp_asn.number":14340,"resp_asn.organization":"SALESFORCE"}
```

## TODO

- Maybe i will add an expiration timer for the records.
- Add more enrich information based on DHCP Options (like Router,ntp server,dns servers) #if they have internal ips.
- Test it on cluster mode with seperated nodes
- Move Event `entity_found` to Proxy or Master Nodes with Broker
- Test it and find bugs that maybe i missed.
- Write a better README.
