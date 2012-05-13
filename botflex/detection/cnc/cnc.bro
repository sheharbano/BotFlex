##! This script looks for possible CnC communication between our hosts
##! and a botnet CnC server. For the time being, we look at (i) blacklist matches
##! (ii) high dns failure rate which hints at botnets that use domain flux (domain
##! generation algorithm <http://en.wikipedia.org/wiki/Domain_Generation_Algorithm> ) 


@load botflex/utils/types
@load botflex/config
@load botflex/services/blacklist_mgr

module CNC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		dns_failures:	   count	    &log;
		ip_cnc:	           string           &log;
		ip_rbn:	           string           &log;
		url_cnc:	   string           &log; 
		url_cnc_dns:       string           &log; 
		msg:		   string           &log;
	};
	
	redef record connection += {
	conn: Info &optional;};

	## The contributory factors (or tributaries) to major event cnc
	type cnc_tributary: enum { Dns_failure, Blacklist_cnc_match, Blacklist_rbn_match, Blacklist_cnc_dns_match };

	## Expire interval for the global table concerned with maintaining cnc info
	const wnd_cnc = 5mins &redef;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	const cnc_evaluation_mode = OR;

	## Thresholds for different contributors to the major event cnc
	const dns_failure_threshold = 20 &redef;
	const cnc_blacklist_match_threshold = 0 &redef;
	const cnc_dns_blacklist_match_threshold = 0 &redef;
	const rbn_blacklist_match_threshold = 0 &redef;

	## Event that can be handled to access the cnc
	## record as it is sent on to the logging framework.
	global log_cnc: event(rec: Info);

	## The event that sufficient evidence has been gathered to declare the
	## CnC phase of botnet infection lifecycle
	global cnc: event( ts: time, src_ip: addr, msg: string, ip_cnc: string, url_cnc: string,
			   url_cnc_dns: string, ip_rbn: string );
}

## Type of the value of the global table table_cnc
## Additional contributary factors that increase the confidence
## about major event egg_download should be added here 
type CncRecord: record {
    tb_tributary: table[ cnc_tributary ] of bool;
    n_dns_failures: count &default=0;		
    ip_cnc: string &default="";
    url_cnc: string &default="";  	
    url_cnc_dns: string &default="";  	
    ip_rbn: string &default="";
    reported_ip: set[addr];
    reported_url: set[string];			
};


## The event that 'dns_failure_threshold' number of failed dns queries
## were observed. This may hint at the use of domain flux as in the case
## of certain botnets such as Torpig and Conficker 
global dns_failure: event( src_ip: addr );

## The event that a host was found to communicate with CnC server ip
## or url from our blacklists
global cnc_url_match: event( src_ip: addr, cnc_url: string );

## The event that a host was found to communicate with CnC server ip
## from our blacklists
global cnc_ip_match: event( src_ip: addr, cnc_ip: addr );

event bro_init()
	{
	Log::create_stream(CNC::LOG, [$columns=Info, $ev=log_cnc]);
	if ( "cnc" in Config::table_config  )
			{
			if ( "th_dns_failure" in Config::table_config["cnc"] )
				{
				dns_failure_threshold = to_count(Config::table_config["cnc"]["th_dns_failure"]);
				}
			if ( "wnd_cnc" in Config::table_config["cnc"] )
				{
				wnd_cnc = string_to_interval(Config::table_config["cnc"]["wnd_cnc"]);
				}
			if ( "evaluation_mode" in Config::table_config["cnc"] )
				{
				cnc_evaluation_mode = string_to_evaluationmode(Config::table_config["cnc"]["evaluation_mode"]);
				}
			}
	}

global cnc_info: CNC::Info;

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[cnc_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[cnc_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[cnc_tributary] of bool ): bool
	{
	local t = 0;
	local f = 0;
	for ( rec in tb )
		{
		if ( tb[rec] )
			++t;
		else
			++f;
		}

	if ( f > t )
		return F;
	else
		return T;
	}

## The function that decides whether or not the major event cnc should
## be generated. It is called (i) every time an entry in the global table table_cnc
## reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 
function evaluate( src_ip: addr, t: table[addr] of CncRecord ): bool
	{
	local do_report: bool;
	if ( cnc_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( cnc_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( cnc_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{
		local msg = "";
		if( t[src_ip]$tb_tributary[ Dns_failure ] ) 
			msg = msg + "High DNS failure rate, possible use of botnet domain flux;";
			
		if ( t[src_ip]$tb_tributary[ Blacklist_cnc_match ] )
			msg = msg + "Host contacted known C&C ip/url;";

		if ( t[src_ip]$tb_tributary[ Blacklist_rbn_match ] )
			msg = msg + "Host contacted RBN ip/url;";

		if ( t[src_ip]$tb_tributary[ Blacklist_cnc_dns_match ] )
			msg = msg + "Host made dns queries about known C&C url;";

    		event CNC::cnc( network_time(), src_ip, msg, t[src_ip]$ip_cnc, t[src_ip]$url_cnc, 
				t[src_ip]$url_cnc_dns, t[src_ip]$ip_rbn);		
	
		## Log cnc related entries
		cnc_info$ts = network_time();
		cnc_info$src_ip = src_ip;
		cnc_info$dns_failures = t[src_ip]$n_dns_failures;
		cnc_info$ip_cnc = t[src_ip]$ip_cnc;
		cnc_info$ip_rbn = t[src_ip]$ip_rbn;
		cnc_info$url_cnc = t[src_ip]$url_cnc;
		cnc_info$url_cnc_dns = t[src_ip]$url_cnc_dns;
		cnc_info$msg = msg;

		Log::write(CNC::LOG,cnc_info);
			
		return T;
		}
	return F;
	}


## Called when an entry in the global table table_cnc exceeds certain age, as specified
## in the table attribute create_expire.
function cnc_record_expired(t: table[addr] of CncRecord, idx: any): interval
	{
	evaluate( idx, t );
	return 0secs;
	}

function get_cnc_record(): CncRecord
	{
	local rec: CncRecord;
	
	local r_url: set[string]; 
	rec$reported_url = r_url;

	local r_ip: set[addr]; 
	rec$reported_ip = r_ip;

	return rec;
	}

## The global state table that maintains various information pertaining to the
## major event cnc, and is analyzed when a decision has to be made whether
## or not to declare the major event cnc.
global table_cnc: table[addr] of CncRecord &create_expire=wnd_cnc &expire_func=cnc_record_expired;


event CNC::dns_failure( src_ip: addr )
	{
	if (src_ip !in table_cnc)
		table_cnc[src_ip] = get_cnc_record();

	# Update total number of failed dns queries
	++ table_cnc[src_ip]$n_dns_failures;

	if( table_cnc[src_ip]$n_dns_failures > dns_failure_threshold )
		{
		table_cnc[src_ip]$tb_tributary[ Dns_failure ]=T;
		local done = evaluate( src_ip, table_cnc );

		## Reset dns_failure parameters
		if (done)
			{
			delete table_cnc[src_ip]$tb_tributary[ Dns_failure ];
			table_cnc[src_ip]$n_dns_failures=0;
			}	
		}	
	}


event CNC::cnc_url_match( src_ip: addr, cnc_url: string )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		table_cnc[src_ip] = get_cnc_record();

	# To avoid reporting the same url over and over again
	if ( cnc_url !in table_cnc[src_ip]$reported_url)
		{
		table_cnc[src_ip]$url_cnc = cnc_url;
		table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_match ]=T;
		local done=evaluate( src_ip, table_cnc );

		## Reset cnc_url parameters
		if (done)
			{
			add table_cnc[src_ip]$reported_url[cnc_url];
			delete table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_match ];
			table_cnc[src_ip]$url_cnc = "";
			}
		}		
	}

event CNC::cnc_url_dns_match( src_ip: addr, cnc_url: string )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		table_cnc[src_ip] = get_cnc_record();

	# To avoid reporting the same url over and over again
	if ( cnc_url !in table_cnc[src_ip]$reported_url)
		{
		table_cnc[src_ip]$url_cnc_dns = cnc_url;
		table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_dns_match ]=T;
		local done = evaluate( src_ip, table_cnc );

		## Reset cnc_dns_url parameters
		if (done)
			{
			add table_cnc[src_ip]$reported_url[cnc_url];
			delete table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_dns_match ];
			table_cnc[src_ip]$url_cnc_dns = "";
			}
		}		
	}


event CNC::cnc_ip_match( src_ip: addr, cnc_ip: addr )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		table_cnc[src_ip] = get_cnc_record();

	# To avoid reporting the same ip over and over again
	if ( cnc_ip !in table_cnc[src_ip]$reported_ip)
		{
		table_cnc[src_ip]$ip_cnc = fmt("%s",cnc_ip);
		table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_match ]=T;
		local done=evaluate( src_ip, table_cnc );

		## Reset cnc_ip parameters
		if (done)
			{
			add table_cnc[src_ip]$reported_ip[cnc_ip];
			delete table_cnc[src_ip]$tb_tributary[ Blacklist_cnc_match ];
			table_cnc[src_ip]$ip_cnc="";
			}
		}	
	}

event CNC::rbn_ip_match( src_ip: addr, rbn_ip: addr )
	{
	## src_ip seen for the first time
	if (src_ip !in table_cnc)
		table_cnc[src_ip] = get_cnc_record();

	# To avoid reporting the same ip over and over again
	if ( rbn_ip !in table_cnc[src_ip]$reported_ip)
		{
		table_cnc[src_ip]$ip_rbn = fmt("%s",rbn_ip);
		table_cnc[src_ip]$tb_tributary[ Blacklist_rbn_match ]=T;
		local done=evaluate( src_ip, table_cnc );

		## Reset rbn_ip parameters
		if (done)
			{
			add table_cnc[src_ip]$reported_ip[rbn_ip];
			delete table_cnc[src_ip]$tb_tributary[ Blacklist_rbn_match ];
			table_cnc[src_ip]$ip_rbn = "";
			}
		}	
			
	}

## Handling the default dns_message event to detect dns NXDOMAIN replies
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local id = c$id;
	local outbound = Site::is_local_addr(id$orig_h);
	if ( msg$rcode == 3 && outbound )
		{
		event CNC::dns_failure(id$orig_h);
		}
	}

## Check if a requested dns query exists in cnc url blacklist
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local outbound = Site::is_local_addr(c$id$orig_h);
	## FIXME: Add whitelist check
	if ( outbound && c$dns$qtype_name == "A" )
		{
		if ( query in BlacklistMgr::tb_blacklists["cnc_url"] )
			event CNC::cnc_url_dns_match( c$id$orig_h, query );
		}
	}

event connection_established( c: connection )
	{
	local src: addr;
	local bad_ip: addr;
	local outbound = Site::is_local_addr(c$id$orig_h);

	src = outbound? c$id$orig_h: c$id$resp_h;
	bad_ip = outbound? c$id$resp_h: c$id$orig_h;

	if ( fmt("%s",bad_ip) in BlacklistMgr::tb_blacklists["cnc_ip"] )
		{
		event CNC::cnc_ip_match( src, bad_ip );
		}
	if ( fmt("%s",bad_ip) in BlacklistMgr::tb_blacklists["rbn_ip"]  )
		event CNC::rbn_ip_match( src, bad_ip );
	for ( snet in BlacklistMgr::blacklist_rbn_subnet )
		{
		if ( bad_ip in snet )
			event CNC::rbn_ip_match( src, bad_ip );
		}	
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	local outbound = Site::is_local_addr(c$id$orig_h);
	local our_ip = outbound? c$id$orig_h: c$id$resp_h;
	local other_ip = outbound? c$id$resp_h: c$id$orig_h;

	if ( c$http$host in BlacklistMgr::tb_blacklists["cnc_url"] )
		event CNC::cnc_url_match( our_ip, c$http$host ); 		
		
	}

