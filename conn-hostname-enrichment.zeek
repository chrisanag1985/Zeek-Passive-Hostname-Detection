redef record conn_id += {

		## The Hostname of the orig_h
		orig_hostname: string &log &optional;
		## The Hostname of the resp_h
		resp_hostname: string &log &optional;

};


function find_hostname(ip: addr): string{

			local hostname = Passive_Entities::entity[ip]$hostname;
			if (Passive_Entities::entity[ip]?$domain)
					hostname = cat(hostname,"[",Passive_Entities::entity[ip]$domain,"]");
					
			return  hostname;

	}

event new_connection(c: connection) &priority=4
{

 	local orig_h = c$id$orig_h;
	local resp_h = c$id$resp_h;
	if ( !(c$id$orig_p == 68/udp && c$id$resp_p == 67/udp)){
		if ( orig_h in Passive_Entities::entity){
			 	c$id$orig_hostname = find_hostname(orig_h);
		}
		if ( resp_h in Passive_Entities::entity){
			 	c$id$resp_hostname = find_hostname(resp_h);
				}
	}



}
