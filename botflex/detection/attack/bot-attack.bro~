##! This script analyzes attack behavior of potential bots. For the
##! time being, we look at spam, sql injection, outbound scan and egg upload

@load botflex/utils/types
@load botflex/config
@load botflex/detection/egg/egg
@load botflex/detection/scan/botflex-scan
@load botflex/detection/attack/spam
@load botflex/detection/attack/sqli

module Attack;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time              &log;
		src_ip:		   addr              &log;
		msg:               string            &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;
	};

	## The contributory factors (or tributaries) to major event bot-attack
	type attack_tributary: enum { Spam, Sqli, Scan, Egg_upload };

	## Expire interval for the global table concerned with maintaining bot-attack info
	const wnd_attack = 60mins &redef;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	const attack_evaluation_mode = OR;

	## The table that maps attack_tributary enum values to strings
	global tb_tributary_string: table[ attack_tributary ] of string &redef; 

	## Thresholds for different contributors to the major event attack
	const spam_threshold = 0 &redef;
	const scan_threshold = 0 &redef;
	const sqli_threshold = 0 &redef;
	const egg_upload_threshold = 0 &redef;
	
	## Event that can be handled to access the attack
	## record as it is sent on to the logging framework.
	global log_attack: event(rec: Info);

       }

## Type of the value of the global table table_attack
## Additional contributary factors that increase the confidence
## about major event attack should be added here 
type AttackRecord: record {
	tb_tributary: table[ attack_tributary ] of bool;
	# For now, these scores are on/off switches. Later, if some weighting
	# mechanism is added, the scores will have to be evaluated.
	score_spam: count &default=0;
	score_scan: count &default=0; 
	score_sqli: count &default=0;
	score_egg_upload: count &default=0;     	
};

## The event that sufficient evidence has been gathered to declare the
## attack phase of botnet infection lifecycle
global attack: event( ts: time, src_ip: addr, msg: string );

event bro_init()
	{
	Log::create_stream( Attack::LOG, [$columns=Info, $ev=log_attack] );
	if ( "attack" in Config::table_config  )
			{
			if ( "th_spam" in Config::table_config["attack"] )
				{
				spam_threshold = to_count(Config::table_config["attack"]["th_spam"]);
				}
			if ( "th_scan" in Config::table_config["attack"] )
				{
				scan_threshold = to_count(Config::table_config["attack"]["th_scan"]);
				}
			if ( "th_egg_upload" in Config::table_config["attack"] )
				{
				egg_upload_threshold = to_count(Config::table_config["attack"]["egg_upload"]);
				}
			if ( "th_sqli" in Config::table_config["attack"] )
				{
				sqli_threshold = to_count(Config::table_config["attack"]["th_sqli"]);
				}
			if ( "wnd_attack" in Config::table_config["attack"] )
				{
				wnd_attack = string_to_interval(Config::table_config["attack"]["wnd_attack"]);
				}
			if ( "evaluation_mode" in Config::table_config["attack"] )
				{
				attack_evaluation_mode = string_to_evaluationmode(Config::table_config["attack"]["evaluation_mode"]);
				}
			}
	}

global attack_info:Attack::Info;

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[attack_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[attack_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[attack_tributary] of bool ): bool
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


## The function that decides whether or not the major event attack should
## be generated. It is called (i) every time an entry in the global table 
## table_attack reaches certain age defined by the table attribute &create_expire,
## or (ii) Any of the counters for a source ip exceed their fixed thresholds. 
function evaluate( src_ip: addr, t: table[addr] of AttackRecord ): bool
	{
	local do_report: bool;
	if ( attack_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( attack_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( attack_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{
		## Other contributory factors to the event attack should
		## be appended to this msg.
		local msg = "";
		for ( rec in t[src_ip]$tb_tributary )
			msg = msg + tb_tributary_string[rec] + ",";
		
    		event attack( network_time(), src_ip, msg );		

		## Log attack related entries
		attack_info$ts = network_time();
		attack_info$src_ip = src_ip;
		attack_info$msg = msg;

		Log::write(Attack::LOG,attack_info);

		return T;
		}
	return F;
	}

## Called when an entry in the global table table_attack exceeds certain age, as specified
## in the table attribute create_expire.
function attack_record_expired(t: table[addr] of AttackRecord, idx: any): interval
	{
	evaluate( idx, t );
	return 0secs;
	}


## The global state table that maintains various information pertaining to the
## major event attack, and is analyzed when a decision has to be made whether
## or not to declare the major event attack
global table_attack: table[addr] of AttackRecord &create_expire=45mins &expire_func=attack_record_expired;

function get_attack_record(): AttackRecord
	{
	local rec: AttackRecord;
	return rec;
	}

event Spam::spam( ts: time, src_ip: addr, msg: string )
	{
	if (src_ip !in table_attack)
		table_attack[src_ip] = get_attack_record();

	# Update spam score
	++ table_attack[src_ip]$score_spam;	
	
	if ( table_attack[src_ip]$score_spam > spam_threshold )
		{
		tb_tributary_string[ Spam ] = msg;
		table_attack[src_ip]$tb_tributary[ Spam ] = T;
		local done = evaluate( src_ip, table_attack );

		## Reset dns_failure parameters
		if (done)
			{
			delete table_attack[src_ip]$tb_tributary[ Spam ];
			table_attack[src_ip]$score_spam=0;
			}	
		}		
	}


event Sqli::sqli( ts: time, src_ip: addr, uris: string, msg: string )
	{
	if (src_ip !in table_attack)
		table_attack[src_ip] = get_attack_record();

	# Update sqli score
	++ table_attack[src_ip]$score_sqli;	
	
	if ( table_attack[src_ip]$score_sqli > sqli_threshold )
		{
		tb_tributary_string[ Sqli ] = msg;
		table_attack[src_ip]$tb_tributary[ Sqli ] = T;
		local done = evaluate( src_ip, table_attack );

		## Reset dns_failure parameters
		if (done)
			{
			delete table_attack[src_ip]$tb_tributary[ Sqli ];
			table_attack[src_ip]$score_sqli=0;
			}	
		}	
	}

event Botflex_scan::scan_ob( ts: time, src_ip: addr, target_port: port, msg: string )
	{
	if (src_ip !in table_attack)
		table_attack[src_ip] = get_attack_record();

	# Update scan score
	++ table_attack[src_ip]$score_scan;	
	
	if ( table_attack[src_ip]$score_scan > scan_threshold )
		{
		tb_tributary_string[ Scan ] = msg;
		table_attack[src_ip]$tb_tributary[ Scan ] = T;
		local done = evaluate( src_ip, table_attack );

		## Reset dns_failure parameters
		if (done)
			{
			delete table_attack[src_ip]$tb_tributary[ Scan ];
			table_attack[src_ip]$score_scan=0;
			}	
		}
	}

event Egg::egg_upload(ts: time, src_ip: addr, egg_url: string, md5: string, msg: string )
	{
	if (src_ip !in table_attack)
		table_attack[src_ip] = get_attack_record();

	# Update spam score
	++ table_attack[src_ip]$score_egg_upload;	
	
	if ( table_attack[src_ip]$score_egg_upload > egg_upload_threshold )
		{
		tb_tributary_string[ Egg_upload ] = msg;
		table_attack[src_ip]$tb_tributary[ Egg_upload ] = T;
		local done = evaluate( src_ip, table_attack );

		## Reset dns_failure parameters
		if (done)
			{
			delete table_attack[src_ip]$tb_tributary[ Egg_upload ];
			table_attack[src_ip]$score_egg_upload=0;
			}	
		}
	}
