##! Manages our blacklists

module BlacklistMgr;

type IdxIp: record {
        bad_ip: addr;
};

type IdxPort: record {
        bad_port: count;
};

type IdxUrl: record {
        bad_url: string;
};

type IdxSubnet: record {
        bad_subnet: subnet;
};

type ValBlacklist: record {
	blacklist_source: string;
        timestamp: time;
	reason: string;
};


export {

	## The full name of blacklist files
	global filename_blacklist_ip="blacklist_ip.txt";
	global filename_blacklist_url="blacklist_url.txt";
	global filename_blacklist_subnet="blacklist_subnet.txt";
	global filename_blacklist_port="blacklist_port.txt";

	## The prefix for blacklist files.The file blacklist_srcfile contains
	## only filenames, such as cnc_url.txt etc. The actual path where this
	## file will be found is specified by the variable below.
	global prefix_blacklist = "/usr/local/bro/share/bro/site/botflex/blacklists/" &redef;	
	#global prefix_blacklist = "/home/sheharbano/Desktop/try/" &redef;

	## Tables for holding the actual blacklists
	## Each blacklist is a table of the form
	## table<key,reason> of <src,ts>
	## key: a (ip|subnet|port|url) value
	## reason: (CnC,Exploit,RBN,Vulnerable)
	## src: the source from which the blacklist was obtained
	## ts: timestamp when the blacklist was acquired
	global blacklist_ip: table[addr] of ValBlacklist = table();
	global blacklist_url: table[string] of ValBlacklist = table();
	global blacklist_subnet: table[subnet] of ValBlacklist = table();
	# This is my hacky table to get around the fact that input framework does
	# not support reading port type as of now, so port is count 
	global blacklist_port_count: table[count] of ValBlacklist = table();
	# The good table where i convert count to port type
	global blacklist_port: table[port] of ValBlacklist = table();	
}

event bro_init() &priority=25 
	{
	local path_bl = fmt("%s%s",prefix_blacklist,filename_blacklist_ip);
	print fmt("Reading in IP address blacklist from %s...",path_bl);
	Input::add_table([$source=path_bl, $name="bl_ip_stream", $idx=IdxIp, $val=ValBlacklist, 					 					$destination=BlacklistMgr::blacklist_ip, $mode=Input::REREAD]);
	Input::remove("bl_ip_stream");	

	path_bl = fmt("%s%s",prefix_blacklist,filename_blacklist_url);
	print fmt("Reading in URL blacklist from %s...",path_bl);
	Input::add_table([$source=path_bl, $name="bl_url_stream", $idx=IdxUrl, $val=ValBlacklist, 					$destination=BlacklistMgr::blacklist_url, $mode=Input::REREAD]);
	Input::remove("bl_url_stream");	

	# GIVES WARNING ON TRAILING ^m AFTER SUBNET VALUE
	path_bl = fmt("%s%s",prefix_blacklist,filename_blacklist_subnet);
	print fmt("Reading in subnet blacklist from %s...",path_bl);
	Input::add_table([$source=path_bl, $name="bl_subnet_stream", $idx=IdxSubnet, $val=ValBlacklist, 					$destination=BlacklistMgr::blacklist_subnet, $mode=Input::REREAD]);
	Input::remove("bl_subnet_stream");	

	# NO SUPPORT FOR READING PORTS IN INPUT FRAMEWORK
	path_bl = fmt("%s%s",prefix_blacklist,filename_blacklist_port);
	print fmt("Reading in vulnerable ports info from %s...",path_bl);
	Input::add_table([$source=path_bl, $name="bl_port_stream", $idx=IdxPort, $val=ValBlacklist, 					$destination=BlacklistMgr::blacklist_port_count, $mode=Input::REREAD]);
	Input::remove("bl_port_stream");	
	}

event Input::end_of_data(name: string, source: string) 
	{ 
	if ( name == "bl_port_stream" )
		{
		local idx: IdxPort; 
		for ( [bad_port] in BlacklistMgr::blacklist_port_count )
			{
			local val = BlacklistMgr::blacklist_port_count[bad_port];
			BlacklistMgr::blacklist_port[count_to_port(bad_port,tcp)] = val;
			}
		}

	}

