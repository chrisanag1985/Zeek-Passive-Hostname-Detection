
export {

	redef record Conn::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record HTTP::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record DNS::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record Notice::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record SSL::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record SSH::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record NTP::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record Weird::Info += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record SMB::FileInfo += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};
	redef record SMB::TreeInfo += {

		orig_hostname: string &log &optional;
		resp_hostname: string &log &optional;
	};

}



function find_hostname(ip: addr): string{

	return	Passive_Hostname_Detection::hostnames_monitor[ip]$hostname;
}


hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter){


 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;

	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){

		if ( rec?$service && rec$service == "dhcp"){}
		else{
		 	rec$orig_hostname = find_hostname(orig_h);
		}
	}	
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		if ( rec?$service && rec$service == "dhcp"){}
		else{
		 	rec$resp_hostname = find_hostname(resp_h);
		}
	}	
}

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}

hook Notice::log_policy(rec: Notice::Info, id: Log::ID, filter: Log::Filter){

	if (rec?$id){
	if (rec$id?$orig_h){
		local orig_h = rec$id$orig_h;
		if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
		}
	}
	if (rec$id?$resp_h){
		local resp_h = rec$id$resp_h;
		if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
				rec$resp_hostname = find_hostname(resp_h);
		}
	}	
	}
}
hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
hook SSH::log_policy(rec: SSH::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
hook NTP::log_policy(rec: NTP::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
hook Weird::log_policy(rec: Weird::Info, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
hook SMB::log_policy_files(rec: SMB::FileInfo, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
hook SMB::log_policy_mapping(rec: SMB::TreeInfo, id: Log::ID, filter: Log::Filter){

 	local orig_h = rec$id$orig_h;
	local resp_h = rec$id$resp_h;
	if ( orig_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$orig_hostname = find_hostname(orig_h);
	}
	if ( resp_h in Passive_Hostname_Detection::hostnames_monitor){
		 	rec$resp_hostname = find_hostname(resp_h);
	}

}
