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

type Idx: record {
        parameter: string;
};

type Val: record {
        value: string;
};

export {
	global table_config: table[string] of Val;
}

global config_filename = "/usr/local/bro/share/bro/site/botflex/config.txt";

event bro_init() &priority=25
	{
	#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	# Uncomment the following later
	#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	Input::add_table([$source=config_filename, $name="config_stream", $idx=Idx, 
			  $val=Val, $destination=table_config, $mode=Input::REREAD]);
	Input::remove("config_stream");
	
	}

event Input::update_finished(name: string, source: string) 
	{
	if (name == "config_stream")
		{
		print table_config;
		}
	}


