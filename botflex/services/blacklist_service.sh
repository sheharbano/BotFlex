#!/bin/bash

prefix="/usr/local/bro/share/bro/site/botflex/blacklists/"
outfile_blacklist_ip=$prefix"blacklist_ip.txt"
outfile_blacklist_url=$prefix"blacklist_url.txt"
outfile_blacklist_subnet=$prefix"blacklist_subnet.txt"
outfile_blacklist_port=$prefix"blacklist_port.txt"

# Empty the directory to create fresh blacklists every time
rm -R $prefix
mkdir $prefix

#Appending field headers to start of output files
echo "#fields	bad_ip	reason	blacklist_source	timestamp" >> $outfile_blacklist_ip
echo "#fields	bad_url	reason	blacklist_source	timestamp" >> $outfile_blacklist_url
echo "#fields	bad_subnet	reason	blacklist_source	timestamp" >> $outfile_blacklist_subnet
echo "#fields	bad_port	reason	blacklist_source	timestamp" >> $outfile_blacklist_port

#CnC
#-----------------------------------------------------------------
#IP
wget -q -O- "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist" | 
sed '1,6d' | 
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tSpyEyeTracker\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist" | 
sed '1d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tPalevoTracker\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist" | 
sed '1,6d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tZeusTracker\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://www.malwaredomainlist.com/hostslist/ip.txt" | 
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tMalwareDomainList\t"ts}' >> $outfile_blacklist_ip

#URL
wget -q -O- "https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist" | 
sed '1,6d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tSpyEyeTracker\t"ts}' >> $outfile_blacklist_url

wget -q -O- "https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist" | 
sed '1d' | 
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tPalevoTracker\t"ts}' >> $outfile_blacklist_url


wget -q -O- "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist" | 
sed '1,6d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tCnC\tZeusTracker\t"ts}' >> $outfile_blacklist_url


#Exploit
#----------------------------------------------------------------------------
#IP
wget -q -O- "http://www.ciarmy.com/list/ci-badguys.txt" | 
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tExploit\tCiarmy\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://feeds.dshield.org/top10-2.txt" |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$1); print $1"\tExploit\tDShield\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://tcats.stop-spam.org/sibl/sibl.txt" |
awk -v of1=$outfile_blacklist_subnet -v of2=$outfile_blacklist_ip -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$1); if ( $1~/\// ) print $1"\tExploit\tTcats\t"ts >> of1; else print $1"\tExploit\tTcats\t"ts >> of2;}'

wget -q -O- "www.openbl.org/lists/base.txt" | 
sed '1,4d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$1); print $1"\tExploit\tOpenbl\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://www.malwaredomainlist.com/hostslist/ip.txt" |
awk -v ts=$(date +%s) '{sub(/[\r*\n*[:cntrl:]*]+/,"",$1); print $0"\tExploit\tMalwareDomainList\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://rules.emergingthreats.net/blockrules/compromised-ips.txt" |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tExploit\tEmergingThreats Compromised IPs\t"ts}' >> $outfile_blacklist_ip

wget -q -O- "http://rules.emergingthreats.net/blockrules/rbn-malvertisers-ips.txt" |
awk -v of1=$outfile_blacklist_subnet -v of2=$outfile_blacklist_ip -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$1); if ( $1~/\// ) print $0"\tExploit\tEmergingThreats RBN Malvertisers\t"ts >> of1; else print $0"\tExploit\tEmergingThreats RBN Malvertisers\t"ts >> of2;}'

#URL
wget -q -O- "http://www.malwaredomainlist.com/hostslist/hosts.txt" | 
sed '1,6d' | 
awk -v ts=$(date +%s) '{gsub(/[\r\n[:cntrl:]]+/,"",$2); print $2"\tExploit\tMalwareDomainList\t"ts}' >> $outfile_blacklist_url


#URL (Drive by download)
wget -q -O- "http://www.blade-defender.org/eval-lab/blade.csv" | 
cat | 
gawk -v ts=$(date +%s) -F',' '{url=substr($9,9,length($9)-9); sub(/[\r\n[:cntrl:]]+/,"",url); print url"\tExploit\tBlade Defender\t"ts}' >> $outfile_blacklist_url


#SUBNETS (Bogon)
# A packet routed over the public Internet should not 
# have a source address in a bogon range (http://www.team-cymru.org/Services/Bogons/).
wget -q -O- "http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt" | 
sed '/^\#/d' |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$0); print $0"\tExploit\tTeamcymru Bogons\t"ts}' >> $outfile_blacklist_subnet


#RBN
#-----------------------------------------------------------------------
#IP

wget -q -O- "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt" | 
cat |
awk -v of1=$outfile_blacklist_subnet -v of2=$outfile_blacklist_ip -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$1); if ( $1~/\// ) print $1"\tRBN\tEmergingThreats\t"ts >> of1; else print $1"\tRBN\tEmergingThreats\t"ts >> of2;}'



#Ports
#-----------------------------------------------------------------------
#Bad ports
wget -q -O- "http://feeds.dshield.org/topports.txt" |
awk -v ts=$(date +%s) '{sub(/[\r\n[:cntrl:]]+/,"",$2); print $2"\tVulnerable\tDshield\t"ts}' >> $outfile_blacklist_port

#echo "First wget at: "`date()` 
#wget -i $infile_cnc_urls -O $outfile_cnc_urls
#echo "Second wget at: "`date()` 





