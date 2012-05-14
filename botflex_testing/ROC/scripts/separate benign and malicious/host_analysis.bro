##! Based on a list of CnC server list and a list of subnets forming
##! the monitored/local network, this script lists unique active hosts
##! as they form connections. Based on whether a host contacts a known 
##! CnC server from the given list, each unique host is tagged as Bot
##! or Benign (results in host_analyzer.log).    

module HostAnalyzer;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		host:          addr               &log;
		tag:           string             &log;
	};

	global log_host_analyzer: event(rec: Info);
	global our_all_hosts: table[addr] of string &default="benign";
	global cnc_servers: set[string];

	# ==================================================================
	# PROVIDE THE SUBNETS FORMING LOCAL NET HERE 
	# ==================================================================
	global our_subnets: set[subnet] = { 1.1.1.1,2.2.2.2 };
}

event bro_init()
	{
	for ( s in HostAnalyzer::our_subnets )
		add Site::local_nets[ s ];

	# ==================================================================
	# PROVIDE THE PATH TO THE TEXT FILE CONTAINING CNC SERVER LIST HERE
	# Accepted file format: Each line of file represents a single CnC IP
	# ==================================================================
	cnc_servers = read_file("/home/whatever/file.txt");
	print cnc_servers;

	Log::create_stream(HostAnalyzer::LOG, [$columns=Info, $ev=log_host_analyzer]);
	}

event new_connection(c: connection)
	{
	local outbound = Site::is_local_addr(c$id$orig_h);
	local our_host = outbound? c$id$orig_h: c$id$resp_h;
	local other_host = outbound? c$id$resp_h: c$id$orig_h;
    
	# If a host communicates with CnC, tag it as bot
	if ( fmt("%s",other_host) in HostAnalyzer::cnc_servers )
		our_all_hosts[our_host] = "Bot";

	# If our host A communicates with another 'benign' host B,
	# record it only the first time, then wait and see if it
	# communicates with a CnC server in the condition above 
	else
		if ( our_host !in HostAnalyzer::our_all_hosts )
			HostAnalyzer::our_all_hosts[our_host] = "Benign";
		
	}

event bro_done()
	{
	local info: Info;
	
	for ( host in HostAnalyzer::our_all_hosts )
		{
		info$host = host;
		info$tag = HostAnalyzer::our_all_hosts[host];
		
		Log::write(HostAnalyzer::LOG, info);	
		}
	}
