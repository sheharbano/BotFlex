##! This script analyzes the egg-download phase of botnet infection lifecycle.
##! It sets a threshold on the number of malicious binaries seen and
##! the number of exes trasported over http disguised as some other filetype
##! and uses the evaluate() function to decide if the major event egg_download 
##! should be triggered.

@load ./scan

module Sbhunter_scan;

export {
	redef enum Log::ID += { LOG_IB, LOG_OB };

	type Info_ib: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		scan_type:         string	    &log;
		num_ports_scanned: count            &log;
		num_addrs_scanned: count            &log;
		target_port:	   port             &log;
		msg:		   string	    &log;
		victims:           string           &log;
		
	};

	type Info_ob: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		scan_type:         string	    &log;
		num_ports_scanned: count            &log;
		num_addrs_scanned: count            &log;
		target_port:	   port             &log;
		msg:		   string	    &log;
		
	};
	
	redef record connection += {
	conn: Info_ib &optional;};

	redef record connection += {
	conn: Info_ob &optional;};

	## Event that can be handled to access the egg_download
	## record as it is sent on to the logging framework.
	global log_scan_ib: event(rec: Info_ib);
	global log_scan_ob: event(rec: Info_ob);
}

global log_scan: event( ts: time, src_ip: addr, scan_type: string, num_ports_scanned: count,
	       num_addrs_scanned: count, target_port: port, msg: string, victims: string, outbound: bool );

## The event that sufficient evidence has been gathered to declare the
## scan phase of botnet infection lifecycle
global scan_ib: event( ts: time, src_ip: addr, msg: string, victim: addr );
global scan_ob: event( ts: time, src_ip: addr, msg: string );

event bro_init() &priority=5
	{
	Log::create_stream(Sbhunter_scan::LOG_IB, [$columns=Info_ib, $ev=log_scan_ib]);
	Log::create_stream(Sbhunter_scan::LOG_OB, [$columns=Info_ob, $ev=log_scan_ob]);
	
	}
global scan_ib_info: Sbhunter_scan::Info_ib;
global scan_ob_info: Sbhunter_scan::Info_ob;

## Hooking into the notices HTTP::Incorrect_File_Type and HTTP::Malware_Hash_Registry_Match
## to generate sub-events that contribute to the major event egg download

redef Notice::policy += {
       [$pred(n: Notice::Info) = {
	       local outbound: bool;  
	       local m: string;
               if ( n$note == Scan::PortScan )
                       {
			outbound = Site::is_local_addr(n$src);
			if ( outbound )
				{
				event scan_ob( network_time(), n$src, n$msg );
				event Sbhunter_scan::log_scan(network_time(), n$src, "Port Scan", n$n, 0, n$p, 
						              n$msg, "", T );
				}
			else
				{
				event scan_ib( network_time(), n$src, n$msg, n$dst );
				event Sbhunter_scan::log_scan(network_time(), n$src, "Port Scan", n$n, 0, n$p, 
						              n$msg, fmt("%s", n$dst), F );
				}
			#event Egg_Download::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, HTTP::build_url_http(c$http) );
                       }

               else if ( n$note == Scan::AddressScanOutbound )
                       {
			m = fmt("%s: %s",n$msg, n$sub);
			event scan_ob( network_time(), n$src, m );
			event Sbhunter_scan::log_scan(network_time(), n$src, "Address Scan", 0, n$n, 0/tcp, 
						      m, "", T );	
                       }

		else if ( n$note == Scan::AddressScanInbound )
                       {
			local msg_arr = split(n$msg, /[:]/);
			local str_victims = split( msg_arr[2], /[[:blank:]]*/ );
			for ( v in str_victims )
				{
				event scan_ib( network_time(), n$src, n$msg, to_addr(str_victims[v]) );
				}
			event Sbhunter_scan::log_scan(network_time(), n$src, "Address Scan", n$n, 0, n$p, 
						      fmt("%s: %s",msg_arr[1], n$sub), msg_arr[2], F );

                       }

	       else if ( n$note == Scan::LowPortTrolling )
                       {
			outbound = Site::is_local_addr(n$src);
			if ( outbound )
				{
				m = fmt("%s: %s", n$msg, "critical");
				event Sbhunter_scan::log_scan(network_time(), n$src, "Port Scan", n$n, 0, n$p, 
						      m, "", T );
				event scan_ob( network_time(), n$src, m );
				}
			else
				{
				m = fmt("%s: %s", n$msg, "critical");
				event scan_ib( network_time(), n$src, m, n$dst );
				event Sbhunter_scan::log_scan(network_time(), n$src, "Port Scan", n$n, 0, n$p, 
						      m, fmt("%s", n$dst), F );
				}
			#event Egg_Download::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, HTTP::build_url_http(c$http) );
                       }
	
       }]
};


event log_scan( ts: time, src_ip: addr, scan_type: string, num_ports_scanned: count,
	       num_addrs_scanned: count, target_port: port, msg: string, victims: string, outbound: bool )
	{
	if ( outbound )
		{
		scan_ob_info$ts = ts;
		scan_ob_info$src_ip = src_ip;
		scan_ob_info$scan_type = scan_type;
		scan_ob_info$num_ports_scanned = num_ports_scanned;
		scan_ob_info$num_addrs_scanned = num_addrs_scanned;
		#scan_ob_info$target_port = target_port;
		scan_ob_info$msg = msg;

		Log::write(Sbhunter_scan::LOG_OB, Sbhunter_scan::scan_ob_info );
		}
	else
		{
		scan_ib_info$ts = ts;
		scan_ib_info$src_ip = src_ip;
		scan_ib_info$scan_type = scan_type;
		scan_ib_info$num_ports_scanned = num_ports_scanned;
		scan_ib_info$num_addrs_scanned = num_addrs_scanned;
		scan_ib_info$target_port = target_port;
		scan_ib_info$msg = msg;
		scan_ib_info$victims = victims;

		Log::write(Sbhunter_scan::LOG_IB, Sbhunter_scan::scan_ib_info );
		}
	}


