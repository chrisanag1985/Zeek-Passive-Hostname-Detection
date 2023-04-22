@load base/frameworks/cluster
@load base/protocols/dhcp
@load base/utils/directions-and-hosts

module Passive_Entities;

type EntityInfo: record {
	mac: string;
        hostname: string;
	domain: string &optional;
	first_time_seen: time &optional;
};

export {

  const host_tracking = LOCAL_HOSTS &redef;

  # Broker::SQLITE or Broker::MEMORY
  const entities_store_persistency = Broker::MEMORY &redef;

  global entity: table[addr] of EntityInfo &broker_allow_complex_type  &backend=entities_store_persistency;
	global entity_found: event(ip_addr: addr, info: EntityInfo);
}

function do_hygiene(ip_addr: addr,info: EntityInfo)
{
	local to_delete: addr;
	local found: bool = F;

	for ( value in Passive_Entities::entity)
	{
	    if ( value != ip_addr){
				# Found Old Record
				if ( Passive_Entities::entity[value]$mac == info$mac)
				{
					to_delete = value;
					found = T;
					break;
				}
	    }
	}

			# Delete Old Record
			if (found)
				delete Passive_Entities::entity[to_delete];
}

event Passive_Entities::entity_found(ip_addr: addr, info: EntityInfo)
   {

	if ( ip_addr in Passive_Entities::entity)
	{
		if ( Passive_Entities::entity[ip_addr]$mac == info$mac )
		{
			# If changed hostname
			if (Passive_Entities::entity[ip_addr]$hostname == info$hostname)
				return;

		    # Change Hostname
			Passive_Entities::entity[ip_addr]$hostname = info$hostname;
		}
		else
		{
			# Replace Record
			Passive_Entities::entity[ip_addr] = info;
		}
        }
	else
	{
		#Found New IP
		Passive_Entities::entity[ip_addr] = info;
		do_hygiene(ip_addr,info);

   	}
}


hook DHCP::log_policy(rec: DHCP::Info,id: Log::ID, filter:Log::Filter){

	local ip_addr: addr;
	local e: EntityInfo;

	if (!rec?$host_name)
		return;

	e$mac = rec$mac;
	e$hostname = rec$host_name;
	e$first_time_seen = rec$ts;

	if ( rec?$domain )
		e$domain = rec$domain;

  if(rec?$assigned_addr){
		ip_addr = rec$assigned_addr;
		if ( addr_matches_host(ip_addr , host_tracking))
			event Passive_Entities::entity_found(ip_addr,e);
	}

	if ( rec?$requested_addr ){
		ip_addr = rec$requested_addr;
		if ( addr_matches_host(ip_addr , host_tracking))
			event Passive_Entities::entity_found(ip_addr,e);
	}

	if ( rec?$client_addr ){
		ip_addr = rec$client_addr;
		if ( addr_matches_host(ip_addr , host_tracking))
			event Passive_Entities::entity_found(ip_addr,e);
	}

}
