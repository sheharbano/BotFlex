##! This script reads all the configuration information for botflex,
##! which includes thresholds for different scripts and values for other 
##! internal parameters. The input file, config.txt, has the standard format
##! <scan|exploit|egg-download|cnc|attack> <parameter name> <value>
##! The information read from this file is then maintained in a table.
##! The value for a threshold in, say attack, can be obtained like this:
##! th_example = Config::table_config[attack][th_example];
##! All scripts should check at bro_init if interesting threshold values 
##! have been defined. If yes, then overwrite the default with this value,
##! otherwise, leave the default intact.
##! For multiple values, separate with a comma (,) for example
##! config local_net 115.186.0.0/16,115.196.0.0/16
    
module Config;

export {
	global config_filename = "/usr/local/bro/share/bro/site/botflex/config.txt" &redef;
	global table_config: table[string] of table[string] of string;
}


event bro_init() &priority=20
	{
	local lines = read_file( config_filename );

	for ( rec in lines )
		{
		local words = split( rec, /[[:blank:]]*/ );
		# Now words[1] = <scan|exploit|egg-download|cnc|attack>, 
		# words[2] = parameter, words[3] = value
		if ( words[1] !in table_config )
			{
			local tb: table[string] of string;
			table_config[words[1]] = tb;
			}
		table_config[words[1]][words[2]] = words[3];
		}

	## Setting local subnets
	local str_our_nets = table_config["config"]["local_net"];
	local our_nets = split( str_our_nets, /[,]/ );
	
	for ( nt in our_nets )
		add Site::local_nets[ to_subnet(our_nets[nt]) ];
	
	}

