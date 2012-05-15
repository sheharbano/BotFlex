#!/usr/bin/env python

## Script that reads in BotHunter log file and converts it into equivalent Bro log file
## Usage: python BHtoBro.py <BH_log_file_name>
## Output: Bro style log file
##====================================
## @author sheharbano
##====================================

import pdb
import re
import sys
import string
import time
from collections import namedtuple

SEP = '============================== SEPARATOR ================================'
dict_bh = {}
time_pattern = '%m/%d/%Y %H:%M:%S.%f %Z'
BHRecord = namedtuple("BHRecord", 'score infected_target infector_list egg_source_list cnc_list peer_coord_list resource_list observed_start inbound_scan exploit exploit_malware_dns egg_download cnc_traffic cnc_traffic_rbn cnc_dns_checkin outbound_skype_candidate outbound_scan_spp outbound_scan attack_prep peer_coordination declare_bot' )

if __name__ == "__main__":
	if len(sys.argv) < 2:
    		print "usage: %s BotHunter_logfile" % (sys.argv[0])
    		sys.exit(1)

	results = open(sys.argv[1], 'rb').read().split(SEP)

	f = open("bothunter2bro.log", 'w')

  	for result in results:
    			pattern_score = r'^Score.*Infected\ Target'             
		    	matches = re.findall(pattern_score, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Infected Target");
				parts2 = parts1[0].split(":");
				score = parts2[1].strip()

			pattern_infected_target = r'^Infected\ Target.*Infector\ List'             
		    	matches = re.findall(pattern_infected_target, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Infector List");
				parts2 = parts1[0].split(":");
				infected_target = parts2[1].strip()
             		   
			pattern_infector_list = r'^Infector\ List.*Egg\ Source\ List' 
		 	matches = re.findall(pattern_infector_list, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Egg Source List");
				parts2 = parts1[0].split(":");
				infector_list = parts2[1].strip()

			pattern_egg_source_list = r'^Egg\ Source\ List.*C\ &\ C\ List' 
		 	matches = re.findall(pattern_egg_source_list, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("C & C List");
				parts2 = parts1[0].split(":");
				egg_source_list = parts2[1].strip()

			pattern_cnc_list = r'^C\ &\ C\ List.*Peer\ Coord.\ List'  
		 	matches = re.findall(pattern_cnc_list, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Peer Coord. List");
				parts2 = parts1[0].split(":");
				cnc_list = parts2[1].strip()

			pattern_peer_coord_list = r'^Peer\ Coord.\ List.*Resource\ List' 
		 	matches = re.findall(pattern_peer_coord_list, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Resource List");
				parts2 = parts1[0].split(":");
				peer_coord_list = parts2[1].strip()

			pattern_resource_list = r'^Resource\ List.*Observed\ Start' 
		 	matches = re.findall(pattern_resource_list, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("Observed Start");
				parts2 = parts1[0].split(":");
				resource_list = parts2[1].strip()

			pattern_observed_start = r'^Observed\ Start.*Gen.\ Time' 
		 	matches = re.findall(pattern_observed_start, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				if "Report End" in matches[0]:
					parts1 = matches[0].split("Report End");
				elif "Gen. Time" in matches[0]:
					parts1 = matches[0].split("Gen. Time");

				parts2 = parts1[0].partition(":");
				observed_start = parts2[2].strip()

			pattern_gen_time = r'^Gen.\ Time.*INBOUND\ SCAN' 
		 	matches = re.findall(pattern_gen_time, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("INBOUND SCAN");
				parts2 = parts1[0].partition(":");
				gen_time = parts2[2].strip()
				time_pattern = '%m/%d/%Y %H:%M:%S.%f %Z'
				ts = int(time.mktime(time.strptime(gen_time, time_pattern)))

			pattern_inbound_scan = r'^INBOUND\ SCAN.*EXPLOIT\n' 
		 	matches = re.findall(pattern_inbound_scan, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("EXPLOIT\n");
				parts2 = (parts1[0].strip()).partition("\n");
				inbound_scan = parts2[2].strip()

			pattern_exploit = r'^EXPLOIT\n.*EXPLOIT\ MALWARE\ DNS\n' 
		 	matches = re.findall(pattern_exploit, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("EXPLOIT MALWARE DNS\n");
				parts2 = (parts1[0].strip()).partition("\n");
				exploit = parts2[2].strip()

			pattern_exploit_malware_dns = r'^EXPLOIT\ MALWARE\ DNS.*EGG\ DOWNLOAD\n' 
		 	matches = re.findall(pattern_exploit_malware_dns, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("EGG DOWNLOAD\n");
				parts2 = (parts1[0].strip()).partition("\n");
				exploit_malware_dns = parts2[2].strip()

			pattern_egg_download = r'^EGG\ DOWNLOAD.*C\ and\ C\ TRAFFIC\n' 
		 	matches = re.findall(pattern_egg_download, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("C and C TRAFFIC\n");
				parts2 = (parts1[0].strip()).partition("\n");
				egg_download = parts2[2].strip()

			pattern_cnc_traffic = r'^C\ and\ C\ TRAFFIC.*C\ and\ C\ TRAFFIC\ \(RBN\)\n' 
		 	matches = re.findall(pattern_cnc_traffic, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("C and C TRAFFIC (RBN)\n");
				parts2 = (parts1[0].strip()).partition("\n");
				cnc_traffic = parts2[2].strip()

			pattern_cnc_traffic_rbn = r'^C\ and\ C\ TRAFFIC\ \(RBN\).*C\ and\ C\ DNS\ CHECK\-IN\n' 
		 	matches = re.findall(pattern_cnc_traffic_rbn, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("C and C DNS CHECK-IN\n");
				parts2 = (parts1[0].strip()).partition("\n");
				cnc_traffic_rbn = parts2[2].strip()

			pattern_cnc_dns_checkin = r'^C\ and\ C\ DNS\ CHECK\-IN.*OUTBOUND\ SKYPE\ CANDIDATE\n' 
		 	matches = re.findall(pattern_cnc_dns_checkin, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("OUTBOUND SKYPE CANDIDATE\n");
				parts2 = (parts1[0].strip()).partition("\n");
				cnc_dns_checkin = parts2[2].strip()

			pattern_outbound_skype_candidate = r'^OUTBOUND\ SKYPE\ CANDIDATE.*OUTBOUND\ SCAN\ \(spp\)\n' 
		 	matches = re.findall(pattern_outbound_skype_candidate, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("OUTBOUND SCAN (spp)\n");
				parts2 = (parts1[0].strip()).partition("\n");
				outbound_skype_candidate = parts2[2].strip()

			pattern_outbound_scan_spp = r'^OUTBOUND\ SCAN\ \(spp\).*OUTBOUND\ SCAN\n' 
		 	matches = re.findall(pattern_outbound_scan_spp, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("OUTBOUND SCAN\n");
				parts2 = (parts1[0].strip()).partition("\n");
				outbound_scan_spp = parts2[2].strip()

			pattern_outbound_scan = r'^OUTBOUND\ SCAN\n.*ATTACK\ PREP\n' 
		 	matches = re.findall(pattern_outbound_scan, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("ATTACK PREP\n");
				parts2 = (parts1[0].strip()).partition("\n");
				outbound_scan = parts2[2].strip()

			pattern_attack_prep = r'^ATTACK\ PREP.*PEER\ COORDINATION\n' 
		 	matches = re.findall(pattern_attack_prep, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("PEER COORDINATION\n");
				parts2 = (parts1[0].strip()).partition("\n");
				attack_prep = parts2[2].strip()

			pattern_peer_coordination = r'^PEER\ COORDINATION.*DECLARE\ BOT\n' 
		 	matches = re.findall(pattern_peer_coordination, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("DECLARE BOT\n");
				parts2 = (parts1[0].strip()).partition("\n");
				peer_coordination = parts2[2].strip()

			pattern_declare_bot = r'^DECLARE\ BOT.*tcpslice\ ' 
		 	matches = re.findall(pattern_declare_bot, result , re.MULTILINE | re.DOTALL | re.VERBOSE)
			if len(matches) > 0 :
				parts1 = matches[0].split("tcpslice ");
				parts2 = (parts1[0].strip()).partition("\n");
				declare_bot = parts2[2].strip()
				
			# Make record and save in dictionary
			rec = BHRecord(score, infected_target, infector_list, egg_source_list, cnc_list, peer_coord_list, resource_list, observed_start, inbound_scan, exploit, exploit_malware_dns, egg_download, cnc_traffic, cnc_traffic_rbn, cnc_dns_checkin, outbound_skype_candidate, outbound_scan_spp, outbound_scan, attack_prep, peer_coordination, declare_bot)

			# Enter in dictionary indexed by timestamp when the report was generated
			dict_bh[ts] = rec

	f.write("#separator \\x09\n")
	f.write("#set_separator	,\n")
	f.write("#empty_field	(empty)\n")
	f.write("#unset_field	-\n")
	f.write("#path	dns\n")
	f.write("#fields\tts\tscore\tinfected_target\tinfector_list\tegg_source_list\tcnc_list\tpeer_coord_list\tresource_list\tobserved_start\tinbound_scan\texploit\texploit_malware_dns\tegg_download\tcnc_traffic\tcnc_traffic_rbn\tcnc_dns_checkin\toutbound_skype_candidate\toutbound_scan_spp\toutbound_scan\tattack_prep\tpeer_coordination\tdeclare_bot\n")
	

	for record in dict_bh:
		f.write("%s\t" %(record) )
		for field in dict_bh[record]:
			tmp = re.sub(r'\s*\n\s*', "$", field.strip(), 0, 0)
			tmp2 = re.sub(r'\s{2,}', "", tmp.strip(), 0, 0)
			print field
			print "----------------------------------------------------"
			f.write("%s\t" %(tmp2) )
		f.write("\n")

	f.close()

