##!/bin/bash
## This script lists all the ip's within our internal network that were
## victims or attackers as per different features defined by BotFlex.

## Usage:
## 1) Place this script in the folder where BotFlex generated its log files. 
## 2) In case you haven't already done this, do chmod +x mine_botflex_logs.sh
## 3) ./mine_botflex_logs.sh

## Output:
## All mined ip's are placed in a folder ./detected in relevant files. Scan has 
## a separate folder to itself: ./detected/scan/ib and ./detected/scan/ob. 

##===================================================
## Sheharbano on Mon May 14 12:45:01 PKT 2012
##===================================================

#=========================================== MAKE DIRECTORIES==================================================
mkdir detected
mkdir detected/scan
mkdir detected/scan/ib
mkdir detected/scan/ob

#=============================================== SCAN IB========================================================

# Critical address scan victims
cat botflexscan_log_ib.log | bro-cut scan_type msg victims | awk 'BEGIN{FS="\t"};$1=="Address Scan" && $2~/Critical/{print $3}' | awk '{for(i=1;i<=NF;i++) print $i}' > "detected/scan/ib/scan_addr_c_ib.txt"

# Medium address scan victims
cat botflexscan_log_ib.log | bro-cut scan_type msg victims | awk 'BEGIN{FS="\t"};$1=="Address Scan" && $2~/Medium/{print $3}' | awk '{for(i=1;i<=NF;i++) print $i}' > "detected/scan/ib/scan_addr_m_ib.txt"

# Critical port scan victims
cat botflexscan_log_ib.log | bro-cut scan_type msg victims | awk 'BEGIN{FS="\t"};$1=="Port Scan" && $2~/Critical/{print $3}' | awk '{for(i=1;i<=NF;i++) print $i}' > "detected/scan/ib/scan_port_c_ib.txt"

# Medium port scan victims
cat botflexscan_log_ib.log | bro-cut scan_type msg victims | awk 'BEGIN{FS="\t"};$1=="Port Scan" && $2~/Medium/{print $3}' | awk '{for(i=1;i<=NF;i++) print $i}' > "detected/scan/ib/scan_port_m_ib.txt"


#==============================================SCAN OB===============================================================
# Critical address scan attackers
cat botflexscan_log_ob.log | bro-cut scan_type msg src_ip | awk 'BEGIN{FS="\t"};$1=="Address Scan" && $2~/Critical/{print $3}' > "detected/scan/ob/scan_addr_c_ob.txt"

# Medium address scan attackers
cat botflexscan_log_ob.log | bro-cut scan_type msg src_ip | awk 'BEGIN{FS="\t"};$1=="Address Scan" && $2~/Medium/{print $3}' > "detected/scan/ob/scan_addr_m_ob.txt"

# Critical port scan attackers
cat botflexscan_log_ob.log | bro-cut scan_type msg src_ip | awk 'BEGIN{FS="\t"};$1=="Port Scan" && $2~/Critical/{print $3}' > "detected/scan/ob/scan_port_c_ob.txt"

# Medium port scan attackers
cat botflexscan_log_ob.log | bro-cut scan_type msg src_ip | awk 'BEGIN{FS="\t"};$1=="Port Scan" && $2~/Medium/{print $3}' > "detected/scan/ob/scan_port_m_ob.txt"

#==============================================EXPLOIT===============================================================

cat exploit.log | bro-cut victim_ip msg | awk 'BEGIN{FS="\t"}; $2~/SSH/{print $1}' > "detected/exploit_ssh.txt"

#================================================EGG================================================================

cat egg_log_down.log | bro-cut our_ip msg | awk 'BEGIN{FS="\t"}; $2~/misleading extensions/{print $1}' > "detected/egg_disguised_exe.txt"

#================================================CNC================================================================

cat cnc.log | bro-cut src_ip msg | awk 'BEGIN{FS="\t"}; $2~/DNS failure/{print $1}' > "detected/cnc_dns_failure.txt"

#==================================================ATTACK===========================================================

cat spam.log | bro-cut src_ip msg | awk 'BEGIN{FS="\t"}; $2~/MX/{print $1}' > "detected/attack_spam_mx.txt"
cat spam.log | bro-cut src_ip msg | awk 'BEGIN{FS="\t"}; $2~/SMTP/{print $1}' > "detected/attack_spam_smtp.txt"
cat sqli.log | bro-cut src_ip > "detected/sqli.txt"



