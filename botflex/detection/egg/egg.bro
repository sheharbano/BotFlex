##! This script analyzes the egg-down/upload phase of botnet infection lifecycle.
##! It sets a threshold on the number of malicious binaries seen and
##! the number of exes trasported over http disguised as some other filetype
##! and uses the evaluate() function to decide if the major event egg_download 
##! should be triggered.

@load base/protocols/http
@load protocols/http/detect-MHR
@load botflex/utils/types
@load botflex/config

module Egg;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                	time             &log;
		our_ip:            	addr             &log;
		egg_ip:                 string  	 &log;
		egg_url:                string  	 &log;
		md5:                    string  	 &log;
		disguised_ip:           string  	 &log;
		disguised_url:          string  	 &log;
		msg:  	 	        string  	 &log;
		
	};
	
	redef record connection += {
	conn: Info &optional;};

	## A structure to hold a url along with its md5 hash
	type IpUrlMD5Record: record {
	    ip: addr;
	    url: string &default="";
	    md5: string &default="";	
	};

	## The contributory factors (or tributaries) to major event egg_download/upload
	type egg_tributary: enum { Tcymru_match, Disguised_exe };

	## Expire interval for the global table concerned with maintaining egg_download/upload info
	const wnd_egg = 10mins &redef;

	## The evaluation mode (one of the modes defined in enum evaluation_mode in utils/types)
	const egg_evaluation_mode = OR; 

	## Thresholds for different contributors to the major event of egg download/upload
	const disguised_exe_threshold = 1 &redef;

	const weight_egg_signature_match = 1.0 &redef;
	const weight_disguised_exe = 0.8 &redef;

	## The event that sufficient evidence has been gathered to declare the
	## egg download phase of botnet infection lifecycle
	global egg_download: event( src_ip: addr, weight: double  );

	## Event that can be handled to access the egg_download
	## record as it is sent on to the logging framework.
	global log_egg_download: event(rec: Info);

}


## The event that an exe was trasported over http with some other extension. 
## This is a common approach for delivering malicious binaries to victim machines
global disguised_exe: event( ts: time, src_ip: addr, dst_ip: addr, url: string );

## The event that the md5 hash of an exe matched Team Cymru's malware hash repository
## For more information, please refer to /policy/protocols/http/detect-MHR
global tcymru_match: event( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string );

## Hooking into the notices HTTP::Incorrect_File_Type and HTTP::Malware_Hash_Registry_Match
## to generate sub-events that contribute to the major events egg download/upload

redef Notice::policy += {
       [$pred(n: Notice::Info) = {  
               if ( n$note == HTTP::Incorrect_File_Type && ( /application\/x-dosexec/ in n$msg || /application\/x-executable/ in n$msg ) )
                       {
			local c = n$conn;
			local url = HTTP::build_url_http(c$http);
			# It's ok if the extension is .bin and it carries an exe as that's how some
			# software delivers its updates.
			if ( !( (/bin$/ in url) || (/solidpkg$/ in url) || (/manifest$/ in url) || 
				(/kdl$/ in url) || (/patchmanifest$/ in url) || (/bundle$/ in url) ))
				event Egg::disguised_exe( n$ts, c$id$orig_h, c$id$resp_h, url );
                       }

               else if ( n$note == HTTP::Malware_Hash_Registry_Match )
                       {
			## FIXME: This is a hack to get md5 and url as n$conn$http is uninitialized at this stage
			## As per /policy/protocols/http/detect-MHR, msg_arr[1]=src_ip, msg_arr[2]=md5, msg_arr[3]=url
			local msg_arr = split(n$msg, /[[:blank:]]*/);

			event Egg::tcymru_match( n$ts, n$src, n$dst, msg_arr[3], msg_arr[2] );
                       }
	
       }]
};

## Type of the value of the global table table_egg
## Additional contributary factors that increase the confidence
## about major event egg_download/upload should be added here 
type egg_record_tag: enum { Download, Upload };
type EggRecord: record {
    tag: egg_record_tag;
    tb_tributary: table[ egg_tributary ] of bool;
    egg_ip: string &default="";
    egg_url: string &default="";		 
    md5: string &default="";
    n_disguised_exes: count &default=0;	 	
    disguised_ip: set[string]; 
    disguised_url: set[string];  		
};

event bro_init() &priority=5
	{
	Log::create_stream(Egg::LOG, [$columns=Info, $ev=log_egg_download]);
	}

event Input::update_finished(name: string, source: string) 
	{
	if ( name == "config_stream" )
		{
		if ( "th_disguised_exe" in Config::table_config )
			disguised_exe_threshold = to_count(Config::table_config["th_disguised_exe"]$value);
		else
			print "Can't find Egg::th_disguised_exe";
		
		if ( "wnd_egg" in Config::table_config )
			wnd_egg = string_to_interval(Config::table_config["wnd_egg"]$value);
		else
			print "Can't find Egg::wnd_egg";

		if ( "weight_egg_signature_match" in Config::table_config )
			weight_egg_signature_match = to_double(Config::table_config["weight_egg_signature_match"]$value);
		else
			print "Can't find Egg::weight_egg_signature_match";

		if ( "weight_disguised_exe" in Config::table_config )
			weight_disguised_exe = to_double(Config::table_config["weight_disguised_exe"]$value);
		else
			print "Can't find Egg::weight_disguised_exe";		
		
		if ( "evaluation_mode" in Config::table_config )
			egg_evaluation_mode = string_to_evaluationmode(Config::table_config["evaluation_mode"]$value);
		else
			print "Can't find Egg::evaluation_mode";		
		}
	}

global egg_info: Egg::Info;

## The following set of functions calculate and, or and majority on a table of
## booleans
function get_and( tb : table[egg_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( !tb[rec] )
			return F;
		}
	return T;
	}

function get_or( tb : table[egg_tributary] of bool ): bool
	{
	for ( rec in tb )
		{
		if ( tb[rec] )
			return T;
		}
	return F;	
	}

function get_majority( tb : table[egg_tributary] of bool ): bool
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

## The function that decides whether or not the major event egg_download/upload 
## should be generated. It is called (i) every time an entry in the global table 
## table_egg reaches certain age defined by the table attribute &create_expire, or 
## (ii) Any of the counters for a source ip exceed their fixed thresholds. 
function evaluate( src_ip: addr, t: table[addr] of EggRecord ): bool
	{
	local do_report: bool;
	if ( egg_evaluation_mode == OR )
		do_report = get_or(t[src_ip]$tb_tributary);
	else if ( egg_evaluation_mode == AND )
		do_report = get_and(t[src_ip]$tb_tributary);
	else if ( egg_evaluation_mode == MAJORITY )
		do_report = get_majority(t[src_ip]$tb_tributary);
		
	if( do_report )
		{ 
		## Log egg download related entries
		egg_info$ts = network_time();
		egg_info$our_ip = src_ip;
		egg_info$egg_ip = t[src_ip]$egg_ip; 
		egg_info$egg_url = t[src_ip]$egg_url; 
		egg_info$md5 = t[src_ip]$md5;
		local str_disguised_ip = setstr_to_string(t[src_ip]$disguised_ip, ","); 
		egg_info$disguised_ip = str_disguised_ip;	
		local str_disguised_url = setstr_to_string(t[src_ip]$disguised_url, ","); 
		egg_info$disguised_url = str_disguised_url;

		
		local msg1 = "";
		local weight = 0.0;

		if ( t[src_ip]$tb_tributary[Tcymru_match] )
			{
			msg1 = msg1 + fmt("Host downloaded exe (md5: %s) tagged as malicious by TeamCymru;",
						t[src_ip]$md5);
			weight = weight_egg_signature_match;
			}

		if ( t[src_ip]$tb_tributary[Disguised_exe] )
			{
			msg1 = msg1 + fmt("Host downloaded exe file(s) with misleading extensions (%s);", 
					   setstr_to_string(t[src_ip]$disguised_url,",") );
			weight = weight_disguised_exe;
			}

    		event Egg::egg_download( src_ip, weight );

		egg_info$msg = msg1;
		Log::write(Egg::LOG, egg_info);

		return T;
		}
	return F;
	}


## Called when an entry in the global table table_egg exceeds certain age, as specified
## in the table attribute create_expire.
function egg_record_expired(t: table[addr] of EggRecord, idx: any): interval
	{
	evaluate( idx, t );
	return wnd_egg;
	}

function get_egg_record(): EggRecord
	{
	local rec: EggRecord;

	local s1: set[string];
	rec$disguised_ip = s1; 

	local s2: set[string];
	rec$disguised_url = s2;

	local t: table[ egg_tributary ] of bool &default=F;
	rec$tb_tributary = t;

	return rec;
	}

## The global state table that maintains various information pertaining to the
## major event egg_down, and is analyzed when a decision has to be made
## whether or not to declare the major event egg_download.
global table_egg_download: table[addr] of EggRecord &create_expire=0sec &expire_func=egg_record_expired;

event tcymru_match( ts: time, src_ip: addr, dst_ip: addr, url: string, md5: string )
	{
	local done: bool;
	local outbound = Site::is_local_addr(src_ip);
	local our_ip = outbound? src_ip: dst_ip;
	local other_ip = outbound? dst_ip: src_ip;
 
	## our_ip seen for the first time
	if (our_ip !in table_egg_download)
		table_egg_download[our_ip] = get_egg_record();

	table_egg_download[our_ip]$tag = Download;
	table_egg_download[our_ip]$egg_ip = fmt("%s",other_ip);
	table_egg_download[our_ip]$egg_url = url;
	table_egg_download[our_ip]$tb_tributary[ Tcymru_match ]=T;
	table_egg_download[our_ip]$md5 = md5;

	done = Egg::evaluate( our_ip, table_egg_download );
	if ( done )
		{
		delete table_egg_download[our_ip]$tb_tributary[ Tcymru_match ];
		table_egg_download[our_ip]$egg_ip = "";
		table_egg_download[our_ip]$egg_url = "";
		table_egg_download[our_ip]$md5 = "";			
		} 
	}


event disguised_exe( ts: time, src_ip: addr, dst_ip: addr, url: string )
	{
	local outbound = Site::is_local_addr(src_ip);
	local our_ip = outbound? src_ip : dst_ip;
	local other_ip = outbound? dst_ip : src_ip;

	local done: bool;
	## our_ip seen for the first time
	if ( our_ip !in table_egg_download )
		table_egg_download[our_ip] = get_egg_record();

	table_egg_download[our_ip]$tag = Download;
	++ table_egg_download[our_ip]$n_disguised_exes;
	add table_egg_download[our_ip]$disguised_ip[ fmt("%s",other_ip) ];
	add table_egg_download[our_ip]$disguised_url[ url ];

	if( table_egg_download[our_ip]$n_disguised_exes > disguised_exe_threshold )
		{
		table_egg_download[our_ip]$tb_tributary[ Disguised_exe ]=T;

		done = Egg::evaluate( our_ip, table_egg_download );
		## Reset disguised_exe parameters
		if (done)
			{
			delete table_egg_download[our_ip]$tb_tributary[ Disguised_exe ];
			for ( itm1 in table_egg_download[our_ip]$disguised_url )
				delete table_egg_download[our_ip]$disguised_url[ itm1 ];
			for ( itm2 in table_egg_download[our_ip]$disguised_ip )
				delete table_egg_download[our_ip]$disguised_ip[ itm2 ];
			}
		}

	}
