##! This script analyzes sql injection attack in the (bot_) attack phase of botnet 
##! infection lifecycle. It does this by looking for sql injection related signature
##! in uri's in http requests. It is based on the original detect-sqli.bro in 
##! /policy/protocols/http.

@load botflex/utils/types
@load botflex/config

module Sqli;


export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip: 	   addr		    &log;
		sqli_uri:	   set[string]      &log;
			
	};
	
	redef record connection += {
	conn: Info &optional;
	};
	
	## Expire interval for the global table concerned with maintaining sqli info
	global wnd_sqli = 10mins;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	global sqli_evaluation_mode = OR;

	## The contributory factors (or tributaries) to major event sqli attack
	type sqli_tributary: enum { Signature_match, };

	## The event that sqli.bro reports sql injection attacks
	global sqli: event( src_ip: addr, weight: double );
	
	## Event that can be handled to access the spam
	## record as it is sent on to the logging framework.
	global log_sqli: event(rec: Info);

	## Thresholds for different contributors to the major event bot_attack
	global sqli_attempt_threshold = 5;
		
	global weight_sqli = 0.5;

	## Regular expression is used to match URI based SQL injections.
	const match_sql_injection_uri = 
		  /[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// &redef;
       }

global sqli_info:Sqli::Info;

event bro_init() &priority=5
	{
	Log::create_stream(Sqli::LOG, [$columns=Info, $ev=log_sqli]);
	}

event Input::end_of_data(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_sqli_attempt" in Config::table_config )
			sqli_attempt_threshold = to_count(Config::table_config["th_sqli_attempt"]$value);
		else
			print "Can't find Sqli::th_sqli_attempt";

		if ( "wnd_sqli" in Config::table_config )
			wnd_sqli = string_to_interval(Config::table_config["wnd_sqli"]$value);
		else
			print "Can't find Sqli::wnd_sqli";

		if ( "weight_sqli" in Config::table_config )
			weight_sqli = to_double(Config::table_config["weight_sqli"]$value);
		else
			print "Can't find Sqli::weight_sqli";
		
		if ( "evaluation_mode" in Config::table_config )
			sqli_evaluation_mode = string_to_evaluationmode(Config::table_config["evaluation_mode"]$value );
		else
			print "Can't find Sqli::evaluation_mode";
				
		}
	}


## Type of the value of the global table table_sqli
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here
type SqliRecord: record {
    tb_tributary: table[ sqli_tributary ] of bool;
    n_sqli_attempts: count &default=0;
    sqli_uri: set[string];
};

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[sqli_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[sqli_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[sqli_tributary] of bool ): bool
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

## The function that decides whether or not the major event sqli should
## be generated. It is called (i) every time an entry in the global table table_sqli
## reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds.  
function evaluate( src_ip: addr, t: table[addr] of SqliRecord ): bool
	{
	local do_report: bool;
	if ( sqli_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( sqli_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( sqli_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{
		local msg = "";
		local weight = 0.0;

		if ( t[src_ip]$tb_tributary[ Signature_match ] )
			{
			msg = msg + "HTTP request matched signature for Sql injection attack";
			weight = weight_sqli;
			}

		event Sqli::sqli( src_ip, weight );

		## Log spam-related entries
		sqli_info$ts = network_time();
		sqli_info$src_ip = src_ip;
		sqli_info$sqli_uri = t[src_ip]$sqli_uri;

		Log::write(Sqli::LOG,sqli_info);

		return T;
		}	
	return F;	
	}

## Called when an entry in the global table table_sqli exceeds certain age, as specified
## in the table attribute create_expire.
function sqli_record_expired(t: table[addr] of SqliRecord, idx: any): interval
	{
	evaluate(idx, t);
	return wnd_sqli;
	}

function get_sqli_record(): SqliRecord
	{
	local rec: SqliRecord;
	local set_sqli_victims: set[addr]; 
	local set_sqli_uri: set[string]; 
	rec$sqli_uri = set_sqli_uri;

	local t: table[ sqli_tributary ] of bool &default=F;
	rec$tb_tributary = t;

	return rec;
	}


## The global state table that maintains various information pertaining to the
## major event sql injection attack, and is analyzed when a decision has to be 
## made whether or not to declare the major event sqli.
global table_sqli: table[addr] of SqliRecord &create_expire=0sec &expire_func=sqli_record_expired;	

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	local outbound = Site::is_local_addr(c$id$orig_h);
	if ( outbound )
		{
		if ( match_sql_injection_uri in unescaped_URI )
			{
			local src_ip = c$http$id$orig_h;

			if ( src_ip !in table_sqli )
				table_sqli[src_ip] = get_sqli_record();

			# Update number of sqli attempts
			++ table_sqli[src_ip]$n_sqli_attempts;

			add table_sqli[src_ip]$sqli_uri[unescaped_URI];

			if ( table_sqli[src_ip]$n_sqli_attempts > sqli_attempt_threshold )
				{
				table_sqli[src_ip]$tb_tributary[ Signature_match ]=T;
				local done = evaluate( src_ip, table_sqli );

				## Reset sqli signature match parameters
				if (done)
					{
					delete table_sqli[src_ip]$tb_tributary[ Signature_match ];
					## FIXME : Empty the table?
					table_sqli[src_ip]$n_sqli_attempts=0;
					}		
				}
			}
		}
	}

	


