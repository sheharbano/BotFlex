##! This script looks for possible CnC communication between our hosts
##! and a botnet CnC server. For the time being, we look at (i) blacklist matches
##! (ii) high dns failure rate which hints at botnets that use domain flux (domain
##! generation algorithm <http://en.wikipedia.org/wiki/Domain_Generation_Algorithm> ) 

@load botflex/detection/exploit/exploit
@load botflex/detection/cnc/cnc

event connection_established( c: connection )
	{
	local our_ip: addr;
	local other_ip: addr;
	local outbound = Site::is_local_addr(c$id$orig_h);

	our_ip = outbound? c$id$orig_h: c$id$resp_h;
	other_ip = outbound? c$id$resp_h: c$id$orig_h;

	local bl_source="";	
	local bl_reason="";

	## Bobax check
	if ( outbound  && ( c$id$resp_p == 447/tcp || c$id$resp_p == 447/udp ) )
		event CNC::bobax_match( our_ip, other_ip, c$id$resp_p );

	## See if there is a match in IP blacklist
	if ( [other_ip] in BlacklistMgr::blacklist_ip )
		{
		bl_source = BlacklistMgr::blacklist_ip[other_ip]$blacklist_source;
		bl_reason = BlacklistMgr::blacklist_ip[other_ip]$reason;
		
		if ( bl_reason == "Exploit" )
			event Exploit::ip_blacklist_match( our_ip, other_ip, bl_source );
		else if ( bl_reason == "CnC" )
			event CNC::ip_blacklist_match( our_ip, other_ip, bl_source, bl_reason );
		else if ( bl_reason == "RBN" )
			event CNC::ip_blacklist_match( our_ip, other_ip, bl_source, bl_reason );	
		}
	## Otherwise, check in subnet blacklist
	else
		{
		for ( [ bad_subnet ] in BlacklistMgr::blacklist_subnet )
			{
			if ( other_ip in bad_subnet && bl_reason=="Exploit" )
				{
				bl_source = BlacklistMgr::blacklist_subnet[bad_subnet]$blacklist_source;
				event Exploit::ip_blacklist_match( our_ip, other_ip, bl_source );
				}
			}
		}

	
	}


event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local our_ip: addr;
	local other_ip: addr;

	local outbound = Site::is_local_addr(c$id$orig_h);

	our_ip = outbound? c$id$orig_h: c$id$resp_h;
	other_ip = outbound? c$id$resp_h: c$id$orig_h;

	local bl_source = "";
	local bl_reason = "";

	if ( c$http?$host && c$http?$uri )
		{
		local host = c$http$host;

		if ( [c$http$host] in BlacklistMgr::blacklist_url )
			{
			bl_source = BlacklistMgr::blacklist_url[host]$blacklist_source;
			bl_reason = BlacklistMgr::blacklist_url[host]$reason;
			if ( bl_reason == "Exploit" )
				event Exploit::url_blacklist_match ( our_ip, other_ip, host, bl_source );
			else if ( bl_reason == "CnC" )
				event CNC::url_blacklist_match ( our_ip, other_ip, host, bl_source, "http" );
			}

		# Conficker signature check
		if ( /search\?q=[0-9]+$/ in c$http$uri)
			event CNC::conficker_match( our_ip, other_ip, fmt("%s%s",c$http$host,c$http$uri) );
		}
				
	}

## Check if a requested dns query exists in cnc url blacklist
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local outbound = Site::is_local_addr(c$id$orig_h);

	local bl_source = "";
	local bl_reason = "";

	## FIXME: Add whitelist check
	if ( outbound && (c$dns$qtype_name == "A" || c$dns$qtype_name == "AAAA") )
		{
		if ( [query] in BlacklistMgr::blacklist_url )
			{
			bl_source = BlacklistMgr::blacklist_url[query]$blacklist_source;
			bl_reason = BlacklistMgr::blacklist_url[query]$reason;

			if ( bl_reason == "CnC" )
				event CNC::url_blacklist_match( c$id$orig_h, c$id$resp_h, query, bl_source, "dns" );
			}
		}
	}

