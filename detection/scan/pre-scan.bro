##! A modified version of scan.bro (which can be found in
##! the contributed scripts in Bro's git <PROVIDE LINK> ). This script
##! provides input to botflex-scan.bro.
##! The term critical in the context of address scan means whether the
##! scanned port was critical/severe as per our bad ports blacklist 
##! (/blacklists/bad_ports.txt).
##! Note that we are not looking at udp scans at the moment.
##! Information passed on to botflex-scan.bro:
##!--------------------------------------------------------------------
##! Address scan (inbound/outbound)(critical/normal)
##! Port scan
##! Low port trolling (essentially port scan on ports <1024).
##!--------------------------------------------------------------------

@load botflex/services/blacklist_mgr
@load botflex/config
@load botflex/utils/types
@load base/frameworks/notice/main

module Scan;

export {
	redef enum Notice::Type += {
		## The source has scanned a number of ports.
		PortScan,
		## An internal source has scanned a number of addresses (inside or outside the monitored network).
		AddressScanOutbound,
		## An external source has scanned a number of our own addresses.
		AddressScanInbound,
		## Apparent flooding backscatter seen from source.
		BackscatterSeen,
		## Source touched privileged ports.
		LowPortTrolling,
	};

	# Whether to consider UDP "connections" for scan detection.
	# Can lead to false positives due to UDP fanout from some P2P apps.
	const suppress_UDP_scan_checks = F &redef;

	# Which services should be analyzed when detecting scanning
	# (not consulted if analyze_all_services is set).
	const analyze_services: set[port] &redef;
	const analyze_all_services = T &redef;

	## Thresholds for triggering address and port scan
	global th_addr_scan = 35;
	global th_addr_scan_critical = 20;
	global th_port_scan = 15;
	# Threshold for scanning privileged ports.
	global th_low_port_troll = 10;

	const troll_skip_service = {
		25/tcp, 21/tcp, 22/tcp, 20/tcp, 80/tcp,
	} &redef;

	const addl_web = {
		81/tcp, 443/tcp, 8000/tcp, 8001/tcp, 8080/tcp, }
	&redef;

	const skip_services = { 113/tcp, } &redef;
	const skip_outbound_services = { 21/tcp, addl_web, }
		&redef;

	const skip_scan_sources = {
		255.255.255.255,	# who knows why we see these, but we do
	} &redef;

	const skip_scan_nets: set[subnet] = {} &redef;

	# List of well known local server/ports to exclude for scanning
	# purposes.
	const skip_dest_server_ports: set[addr, port] = {} &redef;

	# Reverse (SYN-ack) scans seen from these ports are considered
	# to reflect possible SYN-flooding backscatter, and not true
	# (stealth) scans.
	const backscatter_ports = {
		80/tcp, 8080/tcp, 53/tcp, 53/udp, 179/tcp, 6666/tcp, 6667/tcp,
	} &redef;

	const report_backscatter: vector of count = {
		20,
	} &redef;

	global check_scan:
		function(c: connection, established: bool, reverse: bool): bool;

	# How many different hosts connected to with a possible
	# backscatter signature.
	global distinct_backscatter_peers: table[addr] of table[addr] of count
		&read_expire = 15 min;
	
	global wnd_addr_scan = 5mins;
	global wnd_port_scan = 5mins;

	global remove_possible_source:
		function(s: set[addr], idx: addr): interval;
	global possible_scan_sources: set[addr]
		&expire_func=remove_possible_source &read_expire = 15 mins;

	global rb_idx: table[addr] of count
			&default=0 &read_expire = 1 days &redef;
	
}

type idx_distinct_peers: record {
    src_ip: addr;
    scanned_port: port;
};


type idx_distinct_ports: record {
    src_ip: addr;
    scanned_ip: addr;
};

## Called when an entry in the global table table_exploit exceeds certain age, as specified
## in the table attribute create_expire.
function distinct_peers_expired(t: table[idx_distinct_peers] of set[addr], idx: any): interval
	{
	return wnd_addr_scan;
	}

function distinct_ports_expired(t: table[idx_distinct_ports] of set[port], idx: any): interval
	{
	return wnd_port_scan;
	}

global distinct_peers: table[idx_distinct_peers] of set[addr] &create_expire=0secs &expire_func=distinct_peers_expired;
global distinct_ports: table[idx_distinct_ports] of set[port] &create_expire=0secs &expire_func=distinct_ports_expired;	

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_addr_scan" in Config::table_config )
			th_addr_scan = to_count(Config::table_config["th_addr_scan"]$value);
		else
			print "Can't find Scan::th_addr_scan";

		if ( "th_addr_scan_critical" in Config::table_config )
			th_addr_scan_critical = to_count(Config::table_config["th_addr_scan_critical"]$value);
		else
			print "Can't find Scan::th_addr_scan_critical";		

		if ( "th_port_scan" in Config::table_config )
			th_port_scan = to_count(Config::table_config["th_port_scan"]$value);
		else
			print "Can't find Scan::th_port_scan";

		if ( "th_low_port_troll" in Config::table_config )
			th_low_port_troll = to_count(Config::table_config["th_low_port_troll"]$value);
		else
			print "Can't find Scan::th_low_port_troll";

		if ( "wnd_addr_scan" in Config::table_config )
			wnd_addr_scan = string_to_interval(Config::table_config["wnd_addr_scan"]$value);
		else
			print "Can't find Scan::wnd_addr_scan";

		if ( "wnd_port_scan" in Config::table_config )
			wnd_port_scan = string_to_interval(Config::table_config["wnd_port_scan"]$value);
		else
			print "Can't find Scan::wnd_port_scan";						
		}
	}


global thresh_check: function(v: vector of count, idx: table[addr] of count,
				orig: addr, n: count): bool;

function check_scan(c: connection, established: bool, reverse: bool): bool
	{
	local id = c$id;

	local service = "ftp-data" in c$service ? 20/tcp
			: (reverse ? id$orig_p : id$resp_p);
	local rev_service = reverse ? id$resp_p : id$orig_p;
	local orig = reverse ? id$resp_h : id$orig_h;
	local resp = reverse ? id$orig_h : id$resp_h;
	local outbound = Site::is_local_addr(orig);

	local idx = [$src_ip = orig, $scanned_port = service];
	local idx_port = [$src_ip = orig, $scanned_ip = resp];
	
	# The following works better than using get_conn_transport_proto()
	# because c might not correspond to an active connection (which
	# causes the function to fail).
	if ( suppress_UDP_scan_checks &&
	     service >= 0/udp && service <= 65535/udp )
		return F;

	if ( service in skip_services && ! outbound )
		return F;

	if ( outbound && service in skip_outbound_services )
		return F;

	if ( orig in skip_scan_sources )
		return F;

	if ( orig in skip_scan_nets )
		return F;

	# Don't include well known server/ports for scanning purposes.
	if ( ! outbound && [resp, service] in skip_dest_server_ports )
		return F;

	if ( ! established &&
		# not established, service not expressly allowed

		# not known peer set
		(idx !in distinct_peers || resp !in distinct_peers[idx]) &&

		# want to consider service for scan detection
		(analyze_all_services || service in analyze_services) )
		{
		if ( reverse && rev_service in backscatter_ports &&
		     # reverse, non-priv backscatter port
		     service >= 1024/tcp )
			{
			if ( orig !in distinct_backscatter_peers )
				{
				local empty_bs_table:
					table[addr] of count &default=0;
				distinct_backscatter_peers[orig] =
					empty_bs_table;
				}

			if ( ++distinct_backscatter_peers[orig][resp] <= 2 &&
			     # The test is <= 2 because we get two check_scan()
			     # calls, once on connection attempt and once on
			     # tear-down.

			     distinct_backscatter_peers[orig][resp] == 1 &&

			     # Looks like backscatter, and it's not scanning
			     # a privileged port.

			     thresh_check(report_backscatter, rb_idx, orig,
					|distinct_backscatter_peers[orig]|)
			   )
				{
				NOTICE([$note=BackscatterSeen, $src=orig,
					$p=rev_service,
					$identifier=fmt("%s", orig),
					$msg=fmt("backscatter seen from %s (%d hosts; %s)",
						orig, |distinct_backscatter_peers[orig]|, rev_service)]);
				}
			}

		else
			{ # done with backscatter check
			
			
			if ( idx !in distinct_peers )
				{
				local s: set[addr];			
				distinct_peers[idx] = s;
				}

			if ( resp !in distinct_peers[idx] )
				add distinct_peers[idx][resp];

			local n = |distinct_peers[idx]|;

			local do_chk = F;

			if ( [service] in BlacklistMgr::blacklist_port )
				do_chk = (n > th_addr_scan_critical);
			else
				do_chk = (n > th_addr_scan);

			## Outbound scanning
			if ( (outbound) && do_chk )
				{
				local submsg = "";
				if ( [service] in BlacklistMgr::blacklist_port )
					submsg = "Critical";
				else
					submsg = "Medium";
			
				delete distinct_peers[idx];

				NOTICE([$note=AddressScanOutbound,
					$src=orig, $p=service,
					$n=n,
					$identifier=fmt("%s-%d", orig, n),
					$msg=fmt("%s has scanned %d hosts (%s)",
					orig, n, service),
					$sub=submsg]);
				}	
			## Inbound scanning	
			if ( (!outbound) && do_chk)
				{
				local subms = "";
				if (  [service] in BlacklistMgr::blacklist_port )
					subms = "Critical";
				else
					subms = "Medium";

				# In case of inbound scan, we need the destination addrs, i.e., the victims in our
				# network. We'll provide that info as a string delimited by ':', appended to the 
				# original msg
				local victims = ":";
				for ( a in distinct_peers[idx] )
					victims = victims + fmt("%s",a) + " ";

				delete distinct_peers[idx];

				NOTICE([$note=AddressScanInbound,
					$src=orig, $p=service,
					$n=n,
					$identifier=fmt("%s-%d", orig, n),
					$msg=fmt("%s has scanned %d hosts (%s)",
						orig, n, service) + victims,
					$sub=subms ]);
				}
			}
		return F;
		}


	if ( established )
		# Don't consider established connections for port scanning,
		# it's too easy to be mislead by FTP-like applications that
		# legitimately gobble their way through the port space.
		return F;

	## Detection of medium severity port scanning
	if ( service > 1024/tcp &&
	     ( idx_port !in distinct_ports || 
	       service !in distinct_ports[idx_port] ))
		{
		if ( idx_port !in distinct_ports )
			{
			local s3: set[port];
			distinct_ports[idx_port] = s3;
			}

		if ( service !in distinct_ports[idx_port] )
			add distinct_ports[idx_port][service];

		if ( |distinct_ports[idx_port]| > th_port_scan)
			{
			local m = |distinct_ports[idx_port]|;
			NOTICE([$note=PortScan, $n=m, $src=orig, $dst=resp,
			$p=service,
			$identifier=fmt("%s-%d", orig, m),
			$msg=fmt("%s has scanned %d ports of %s",
				orig, m, resp), 
				$sub = "Medium"]);
			}
		}

	# Check for low ports.
	if ( service < 1024/tcp &&
	     service !in troll_skip_service )
		{
		if ( idx_port !in distinct_ports )
			{
			local s4: set[port];
			distinct_ports[idx_port] = s4;
			}

		add distinct_ports[idx_port][service];

		if ( |distinct_ports[idx_port]| > th_low_port_troll )
			{
			local svrc_msg = fmt("low port trolling of %s by %s (%s)", resp, orig, service);
			NOTICE([$note=LowPortTrolling, $src=orig, $dst=resp,
				$identifier=fmt("%s", orig),
				$p=service, $msg=svrc_msg, $sub="Critical", $n = |distinct_ports[idx_port]| ]);
			}
			
		}

	return T;
	}

# To recognize whether a certain threshhold vector (e.g. report_peer_scans)
# has been transgressed, a global variable containing the next vector index
# (idx) must be incremented.  This cumbersome mechanism is necessary because
# values naturally don't increment by one (e.g. replayed table merges).
function thresh_check(v: vector of count, idx: table[addr] of count,
			orig: addr, n: count): bool
	{
	if ( idx[orig] <= |v| && n >= v[idx[orig]] )
		{
		++idx[orig];
		return T;
		}
	return F;
	}

event connection_established(c: connection)
	{
	local is_reverse_scan = (c$orig$state == TCP_INACTIVE);
	Scan::check_scan(c, T, is_reverse_scan);
	}

event partial_connection(c: connection)
	{
	Scan::check_scan(c, T, F);
	}

event connection_attempt(c: connection)
	{
	Scan::check_scan(c, F, c$orig$state == TCP_INACTIVE);
	}

event connection_half_finished(c: connection)
	{
	# Half connections never were "established", so do scan-checking here.
	Scan::check_scan(c, F, F);
	}

event connection_rejected(c: connection)
	{
	local is_reverse_scan = c$orig$state == TCP_RESET;

	Scan::check_scan(c, F, is_reverse_scan);
	}

event connection_reset(c: connection)
	{
	if ( c$orig$state == TCP_INACTIVE || c$resp$state == TCP_INACTIVE )
		# We never heard from one side - that looks like a scan.
		Scan::check_scan(c, c$orig$size + c$resp$size > 0,
				c$orig$state == TCP_INACTIVE);
	}

event connection_pending(c: connection)
	{
	if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
		Scan::check_scan(c, F, F);
	}

