##! This script analyzes attack behavior of potential bots. For the
##! time being, we look at spam and a coarse analysis of DDoS like 
##! activity.

module Bot_Attack;

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
	
	## Event that can be handled to access the bot_attack
	## record as it is sent on to the logging framework.
	global log_bot_attack: event(rec: Info);

	## The event that spam.bro reported spam
	global spam: event( src_ip: addr );

	## The event that sqli.bro reported sql injection attacks
	global sqli: event( src_ip: addr, victims: string );

	## The event that sqli.bro reported sql injection attacks
	global breakin: event( victim: addr, attackers: string );
       }

## Type of the value of the global table table_bot_attack
## Additional contributary factors that increase the confidence
## about major event bot_attack should be added here 
type BotAttackRecord: record {
	score_spam: bool;
	score_ddos: bool; 
	score_sqli: bool;     	
};

## The event that sufficient evidence has been gathered to declare the
## bot_attack phase of botnet infection lifecycle
global bot_attack: event( ts: time, src_ip: addr, msg: string );

event bro_init() &priority=5
	{
	Log::create_stream( Bot_Attack::LOG, [$columns=Info, $ev=log_bot_attack] );
	}
global bot_attack_info:Bot_Attack::Info;

## The function that decides whether or not the major event bot_attack should
## be generated. It is called (i) every time an entry in the global table 
## table_bot_attack reaches certain age defined by the table attribute &create_expire,
## or (ii) Any of the counters for a source ip exceed their fixed thresholds. 

function evaluate( src_ip: addr, t: table[addr] of BotAttackRecord )
	{
	if( t[src_ip]$score_spam || t[src_ip]$score_ddos )
		{
		local msg = "";
  		if( t[src_ip]$score_spam )
			msg = msg + "Spam,";
		if( t[src_ip]$score_ddos )
			msg =  msg + "DDoS,";
		if( t[src_ip]$score_ddos )
			msg =  msg + "Sqli,";
		
    		event bot_attack( network_time(), src_ip, msg );		

		## Log bot_attack related entries
		bot_attack_info$ts = network_time();
		bot_attack_info$src_ip = src_ip;
		bot_attack_info$msg = msg;

		Log::write(Bot_Attack::LOG,bot_attack_info);

		## Get rid of the record
		delete t[src_ip];
		}
	}

## Called when an entry in the global table table_bot_attack exceeds certain age, as specified
## in the table attribute create_expire.
function bot_attack_record_expired(t: table[addr] of BotAttackRecord, idx: any): interval
	{
	evaluate( idx, t );
	return 0secs;
	}


## The global state table that maintains various information pertaining to the
## major event cnc, and is analyzed when a decision has to be made whether
## or not to declare the major event cnc.
global table_bot_attack: table[addr] of BotAttackRecord &create_expire=45mins &expire_func=bot_attack_record_expired;

event spam( src_ip: addr )
	{
	if (src_ip !in table_bot_attack)
		{
		local rec: BotAttackRecord;
		rec$score_ddos = F;
		rec$score_spam = F;
		rec$score_sqli = F;

		table_bot_attack[src_ip]=rec;

		}

	# Update spam score
	table_bot_attack[src_ip]$score_spam = T;	
	
	evaluate( src_ip, table_bot_attack );	
	}


event sqli( src_ip: addr, victims: string )
	{
	if (src_ip !in table_bot_attack)
		{
		local rec: BotAttackRecord;
		rec$score_ddos = F;
		rec$score_spam = F;
		rec$score_sqli = T;

		table_bot_attack[src_ip] = rec;

		}

	# Update sqli score
	table_bot_attack[src_ip]$score_sqli = T;	
	
	evaluate( src_ip, table_bot_attack );	
	}
