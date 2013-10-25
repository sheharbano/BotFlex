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
	type cnc_tributary: enum { Dns_failure, Blacklist_cnc_match, Blacklist_rbn_match, 
				   Blacklist_cnc_dns_match, Conficker_match, Bobax_match };

	## Expire interval for the global table concerned with maintaining cnc info
	global wnd_cnc = 5mins;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	global cnc_evaluation_mode = OR;

	## Thresholds for different contributors to the major event cnc
	global dns_failure_threshold = 25;
	global cnc_blacklist_match_threshold = 0;
	global cnc_dns_blacklist_match_threshold = 0;
	global rbn_blacklist_match_threshold = 0;

	global weight_dns_failure = 0.8;
	global weight_cnc_blacklist_match = 1.0;
	global weight_cnc_blacklist_dns_match = 0.5;
	global weight_cnc_signature_match = 0.8;	
	global weight_rbn_blacklist_match = 0.5;

	## Event that can be handled to access the cnc
	## record as it is sent on to the logging framework.
	global log_cnc: event(rec: Info);

	## The event that sufficient evidence has been gathered to declare the
	## CnC phase of botnet infection lifecycle
	global cnc: event( src_ip: addr, weight: double );

	global url_blacklist_match: event( our_ip: addr, other_ip: addr, bad_url: string, bl_source: string, tag: string );
	global ip_blacklist_match: event( our_ip: addr, other_ip: addr, bl_source: string, reason: string );

	## The event that a host was seen to make outbound
	## 447/tcp or 447/udp connections which point to
	## Bobax/Kraken/Oderoor infection
	global bobax_match: event( our_ip: addr, other_ip: addr, bad_port: port );

	## The event that a host was seen to making HTTP request
	## that had a URI that matched Conficker signature i.e.
	## the URI ends with search?q=n
	global conficker_match: event( our_ip: addr, other_ip: addr, bad_url: string );
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
    submsg: string &default="";			
};


## The event that 'dns_failure_threshold' number of failed dns queries
## were observed. This may hint at the use of domain flux as in the case
## of certain botnets such as Torpig and Conficker 
global dns_failure: event( src_ip: addr );

event bro_init()
	{
	Log::create_stream(CNC::LOG, [$columns=Info, $ev=log_cnc]);
	}

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_dns_failure" in Config::table_config )
			dns_failure_threshold = to_count(Config::table_config["th_dns_failure"]$value);
		else
			print "Cannot find CNC::th_dns_failure";

		if ( "wnd_cnc" in Config::table_config )
			wnd_cnc = string_to_interval(Config::table_config["wnd_cnc"]$value);
		else
			print "Cannot find CNC::wnd_cnc";

		if ( "weight_dns_failure" in Config::table_config )
			weight_dns_failure = to_double(Config::table_config["weight_dns_failure"]$value);
		else
			print "Cannot find CNC::weight_dns_failure";

		if ( "weight_cnc_blacklist_match" in Config::table_config )
			weight_cnc_blacklist_match = to_double(Config::table_config["weight_cnc_blacklist_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_blacklist_match";
		
		if ( "weight_cnc_blacklist_dns_match" in Config::table_config )
			weight_cnc_blacklist_dns_match = to_double(Config::table_config["weight_cnc_blacklist_dns_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_blacklist_dns_match";		
	
		if ( "weight_cnc_signature_match" in Config::table_config )
			weight_cnc_signature_match = to_double(Config::table_config["weight_cnc_signature_match"]$value);
		else
			print "Cannot find CNC::weight_cnc_signature_match";			
		
		if ( "weight_rbn_blacklist_match" in Config::table_config )
			weight_rbn_blacklist_match = to_double(Config::table_config["weight_rbn_blacklist_match"]$value);
		else				
			print "Cannot find CNC::weight_rbn_blacklist_match";

		if ( "evaluation_mode" in Config::table_config )
			cnc_evaluation_mode = string_to_evaluationmode(Config::table_config["evaluation_mode"]$value);
		else
			print "Cannot find CNC::evaluation_mode";
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
		local weight = 0.0;

		## FIXME: In future, we might want to accumulate these different weights,
		## especially, when evaluation mode is not OR 
		if( t[src_ip]$tb_tributary[ Dns_failure ] )
			{ 
			msg = msg + "High DNS failure rate, possible use of botnet domain flux;";
			weight = weight_dns_failure;
			}
			
		if ( t[src_ip]$tb_tributary[ Blacklist_cnc_match ] )
			{
			msg = msg + t[src_ip]$submsg;
			weight = weight_cnc_blacklist_match;
			}

		if ( t[src_ip]$tb_tributary[ Blacklist_rbn_match ] )
			{
			msg = msg + t[src_ip]$submsg;
			weight = weight_rbn_blacklist_match;
			}

		if ( t[src_ip]$tb_tributary[ Blacklist_cnc_dns_match ] )
			{
			msg = msg + t[src_ip]$submsg;
			weight = weight_cnc_blacklist_dns_match;
			}

		if ( t[src_ip]$tb_tributary[ Conficker_match ] )
			{
			msg = msg + "Conficker match (search?q=n);";
			weight = weight_cnc_signature_match;
			}

		if ( t[src_ip]$tb_tributary[ Bobax_match ] )
			{
			msg = msg + "Bobax match (outbound 447/tcp or udp);";
			weight = weight_cnc_signature_match;
			}

    		event CNC::cnc( src_ip, weight );		
	
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
	return wnd_cnc;
	}

function get_cnc_record(): CncRecord
	{
	local rec: CncRecord;
	
	local r_url: set[string]; 
	rec$reported_url = r_url;

	local r_ip: set[addr]; 
	rec$reported_ip = r_ip;

	local t: table[ cnc_tributary ] of bool &default=F;
	rec$tb_tributary = t;

	return rec;
	}

## The global state table that maintains various information pertaining to the
## major event cnc, and is analyzed when a decision has to be made whether
## or not to declare the major event cnc.
global table_cnc: table[addr] of CncRecord &create_expire=0sec &expire_func=cnc_record_expired;


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


event CNC::conficker_match( our_ip: addr, other_ip: addr, bad_url: string )
	{
	## src_ip seen for the first time
	if (our_ip !in table_cnc)
		table_cnc[our_ip] = get_cnc_record();

	# To avoid reporting the same url over and over again
	if ( bad_url !in table_cnc[our_ip]$reported_url)
		{
		table_cnc[our_ip]$tb_tributary[ Conficker_match ]=T;
		local done = evaluate( our_ip, table_cnc );

		## Reset parameters
		if (done)
			{
			add table_cnc[our_ip]$reported_url[bad_url];
			delete table_cnc[our_ip]$tb_tributary[ Conficker_match ];
			}
		}		
	}


event CNC::bobax_match( our_ip: addr, other_ip: addr, bad_port: port )
	{
	## src_ip seen for the first time
	if (our_ip !in table_cnc)
		table_cnc[our_ip] = get_cnc_record();

	# To avoid reporting the same ip over and over again
	if ( other_ip !in table_cnc[our_ip]$reported_ip)
		{
		table_cnc[our_ip]$ip_cnc = fmt("%s",other_ip);
		table_cnc[our_ip]$tb_tributary[ Bobax_match ]=T;
		local done=evaluate( our_ip, table_cnc );

		## Reset cnc_ip parameters
		if (done)
			{
			add table_cnc[our_ip]$reported_ip[other_ip];
			delete table_cnc[our_ip]$tb_tributary[ Bobax_match ];
			table_cnc[our_ip]$ip_cnc="";
			}
		}		
	}

## Handling the default dns_message event to detect dns NXDOMAIN replies
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local id = c$id;
	local outbound = Site::is_local_addr(id$orig_h);

	if(c?$dns)
		{
		if ( c$dns?$rcode_name && c$dns?$qtype_name  )
			{
			if ( c$dns$rcode_name=="NXDOMAIN" && (c$dns$qtype_name=="A" || c$dns$qtype_name=="AAAA") && outbound )
				event CNC::dns_failure(id$orig_h);
			}
		}
	}


event CNC::url_blacklist_match( our_ip: addr, other_ip: addr, bad_url: string, bl_source: string, tag: string )
	{
	local done = F;

	## src_ip seen for the first time
	if (our_ip !in table_cnc)
		table_cnc[our_ip] = get_cnc_record();

	if ( tag == "dns" )
		{
		# To avoid reporting the same url over and over again
		if ( bad_url !in table_cnc[our_ip]$reported_url)
			{
			table_cnc[our_ip]$url_cnc_dns = fmt("%s",bad_url);
			table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_dns_match ]=T;
			table_cnc[our_ip]$submsg = table_cnc[our_ip]$submsg+fmt("DNS query for blacklisted URL (source: %s);", bl_source);

			done = evaluate( our_ip, table_cnc );

			## Reset cnc_dns_url parameters
			if (done)
				{
				add table_cnc[our_ip]$reported_url[bad_url];
				delete table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_dns_match ];
				table_cnc[our_ip]$url_cnc_dns = "";
				table_cnc[our_ip]$submsg = "";
				}
			}		
		}
	else if ( tag == "http" )
		{
		# To avoid reporting the same url over and over again
		if ( bad_url !in table_cnc[our_ip]$reported_url)
			{
			table_cnc[our_ip]$url_cnc = fmt("%s(source: %s)",bad_url,bl_source);
			table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_match ]=T;
			table_cnc[our_ip]$submsg = table_cnc[our_ip]$submsg+fmt("HTTP contact with blacklisted URL (source: %s);", bl_source);

			done = evaluate( our_ip, table_cnc );

			## Reset cnc_url parameters
			if (done)
				{
				add table_cnc[our_ip]$reported_url[bad_url];
				delete table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_match ];
				table_cnc[our_ip]$url_cnc = "";
				table_cnc[our_ip]$submsg = "";
				}
			}
		}	
	}


event CNC::ip_blacklist_match( our_ip: addr, other_ip: addr, bl_source: string, reason: string )
	{
	local done = F;

	## src_ip seen for the first time
	if (our_ip !in table_cnc)
		table_cnc[our_ip] = get_cnc_record();

	if ( reason == "CnC" )
		{
		# To avoid reporting the same ip over and over again
		if ( other_ip !in table_cnc[our_ip]$reported_ip)
			{
			table_cnc[our_ip]$ip_cnc = fmt("%s",other_ip);
			table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_match ]=T;
			table_cnc[our_ip]$submsg = table_cnc[our_ip]$submsg+fmt("CnC IP blacklist matched (source: %s);", bl_source);

			done=evaluate( our_ip, table_cnc );

			## Reset cnc_ip parameters
			if (done)
				{
				add table_cnc[our_ip]$reported_ip[other_ip];
				delete table_cnc[our_ip]$tb_tributary[ Blacklist_cnc_match ];
				table_cnc[our_ip]$ip_cnc="";
				table_cnc[our_ip]$submsg="";
				}
			}
		}

	else if ( reason == "RBN" )
		{
		# To avoid reporting the same ip over and over again
		if ( other_ip !in table_cnc[our_ip]$reported_ip)
			{
			table_cnc[our_ip]$ip_rbn = fmt("%s",other_ip);
			table_cnc[our_ip]$tb_tributary[ Blacklist_rbn_match ]=T;
			table_cnc[our_ip]$submsg = table_cnc[our_ip]$submsg+fmt("RBN IP blacklist matched (source: %s);", bl_source);

			done=evaluate( our_ip, table_cnc );

			## Reset rbn_ip parameters
			if (done)
				{
				add table_cnc[our_ip]$reported_ip[other_ip];
				delete table_cnc[our_ip]$tb_tributary[ Blacklist_rbn_match ];
				table_cnc[our_ip]$ip_rbn = "";
				table_cnc[our_ip]$submsg = "";
				}
			}
		}		
	}













