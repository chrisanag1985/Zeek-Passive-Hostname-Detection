module Passive_Hostname_Detection;

type Idx: record {

        ip: addr;

};


type Val: record {
	mac: string;
        hostname: string;
};


export {

	global hostnames_monitor: table[addr] of Val = table();

}


function clear_hostnames_monitor(hostname_del: string,mac_del: string){

	local to_delete: addr;
	local found: bool = F;


	for ( ip,value in hostnames_monitor){

		if ( hostname_del in value$hostname && mac_del in value$mac){
			to_delete = ip;
			found = T;
			break;
			}
		}

	if(found){
 		delete hostnames_monitor[to_delete];
	}

}

event zeek_init(){

	Input::add_table([$source="/var/db/passive_hosts",
		$name="hostnames",
		$idx=Idx,
		$val=Val,
		$destination=hostnames_monitor,
		$reader=Input::READER_SQLITE,
		$config=table(["query"] = "select * from hostnames;")
		]);

	Input::remove("hostnames");



}




hook DHCP::log_policy(rec: DHCP::Info,id: Log::ID, filter:Log::Filter){
	local cmd: string;

        if(rec?$assigned_addr){
        	cmd = fmt("sqlite3 /var/db/passive_hosts.sqlite \"delete from hostnames where hostname='%s' and mac='%s' ;replace into hostnames(mac,ip,hostname) values ('%s','%s','%s');\"",rec$host_name,rec$mac,rec$mac,rec$assigned_addr,rec$host_name);
		clear_hostnames_monitor(rec$host_name,rec$mac);
		hostnames_monitor[rec$assigned_addr] = [$mac=rec$mac,$hostname=rec$host_name];
	}
	if ( rec?$requested_addr ){
        	cmd = fmt("sqlite3 /var/db/passive_hosts.sqlite \"delete from hostnames where hostname='%s' and mac='%s' ;replace into hostnames(mac,ip,hostname) values ('%s','%s','%s');\"",rec$host_name,rec$mac,rec$mac,rec$requested_addr,rec$host_name);
		clear_hostnames_monitor(rec$host_name,rec$mac);
		hostnames_monitor[rec$requested_addr] = [$mac=rec$mac,$hostname=rec$host_name];
	}
	if ( rec?$client_addr ){
        	cmd = fmt("sqlite3 /var/db/passive_hosts.sqlite \"delete from hostnames where hostname='%s' and mac='%s' ;replace into hostnames(mac,ip,hostname) values ('%s','%s','%s');\"",rec$host_name,rec$mac,rec$mac,rec$client_addr,rec$host_name);
		clear_hostnames_monitor(rec$host_name,rec$mac);
		hostnames_monitor[rec$client_addr] = [$mac=rec$mac,$hostname=rec$host_name];
	}



	when [cmd]( local result = Exec::run([$cmd=cmd]))
			{}
}
