BotFlex
(works with Bro version 2.0) 
=====================================================
@author Sheharbano Khattak 
(sheharbano.k@gmail.com)
====================================================

BotFlex is an open source tool for bot detection and analysis tool. Though it was built initially with bots in mind, it works equally well for detection of general Internet malware. This is because BotFlex has been designed to be extremely modular. BotFlex is based on the principle that multiple sources of evidence strengthens the chances of infection, and therefore we maintain state (for some time) of hosts that have been previously observed to be engaged in 'bad' behavior.

====================================================
How to get going:
====================================================

1) Install Bro (http://www.bro-ids.org/documentation/quickstart.html)
2) Download BotFlex from (https://github.com/sheharbano/BotFlex/tree/master/botflex)
3) Move it to /usr/local/bro/share/bro/site/
4) While the defaults work fine, you are *strongly advised* to specify your local network (local_net) in (/usr/local/bro/share/bro/site/botflex/config.txt)
5) For live analysis: bro -i <interface> /usr/local/bro/share/bro/site/botflex/detection/correlation/correlation.bro
       trace file:  bro -r <trace.pcap> /usr/local/bro/share/bro/site/botflex/detection/correlation/correlation.bro


====================================================
How it works:
====================================================

BotFlex comes equipped with the following:

********************
CORRELATION:
********************
Existing approaches are either predominantly signature-based (e.g. Snort), or behavior based (Bro). We want to give you the best of both worlds by using Bro's new input framework (http://blog.bro-ids.org/2012/06/upcoming-loading-data-into-bro-with.html) to *automatically* load in a whole bunch of useful blaklists (from EmergingThreats, ZeusTracker, DShield among others) and combine it with Bro's behavior analysis magic. 

We correlate different events in (/usr/local/bro/share/bro/site/botflex/detection/correlation/correlation.bro) in the function evaluate(). For example, you can say, let me know when you see:
x number of inbound scan events for a host and also y number of attack events.

*******************
ONE-STOP CONFIGURATION:
*******************
The defaults will work fine, but if you are feeling adventurous, take a look at (/usr/local/bro/share/bro/site/botflex/config.txt)
*Everything* is configurable!
Observation windows, thresholds, local subnets, all in one go!

********************
BLACKLISTS:
********************
A blacklist pulling service (/usr/local/bro/share/bro/site/botflex/services/blacklist_service.sh). The list of sources used for compiling the blacklists can be found here (/usr/local/bro/share/bro/site/botflex/services/src_blacklists.txt). The blacklists are downloaded to /usr/local/bro/share/bro/site/botflex/blacklists and are sorted by URLs, IP addresses, Subnets and Ports. The blacklists follow the standard format:
bad_ip	reason	blacklist_source	timestamp


******************
DETECTION:
******************
BotFlex divides suspicious network activity into five classes, and comprises of the following sub components (it can be extended).:

Inbound Scan
-------------
Many bad things start with an inbound scan. So if we see an inbound scan by a host, and then the scanned hosts display some other suspicious activity, there is reason to invetigate further. We look at the following for inbound scan:
--> If we see x number of hosts being scanned on the same port (Inbound IP sweep)
--> Vertical port sweep on one of our internal hosts
--> Critical vs Medium Severity Scan: If the port on which the IP sweep took place has been labeled as high vulnerability by a blacklist (plz check /usr/local/bro/share/bro/site/botflex/blacklists/blacklist_port), we call it a Critical Scan. Otherwise, of course, it is a Medium Severity Scan.

Egg Download
--------------
Download of a questionable file.
-->Seen an exe downloaded with a misleading extension
-->Match with TeamCymru's Malware Hash Registry

Exploit
--------------
Signs that a host was exploited.
--> Match with blacklists of 'bad hosts' found to be trying to root honeypots.
--> Match with blacklist of drive by download URLs
--> SSH brute force attempt

C&C
--------------
Signs of malware remote communication
--> High DNS failure rate (usually true for bots using Domain Generation Algorithm)
--> Bobax and Conficker communication checks 
--> Match with C&C and RBN blacklists

Attack
---------------
Signs of aggressive behavior indicating that the host is compromised
--> Spam (high SMTP failure rate, MX domain queries)
--> Outbound scan (IP sweep on a specific port / vertical port scan )
--> SQL injection attacks

=============================================================
Interpreting log files:
=============================================================

Lets do an example

The correlation.log looks like this:
#fields	ts	host	observation_start	rule_id	scan	exploit	egg_download	cnc	attack
1330440985.389741	x.x.x.x		1330437615.441414	condition2	0	2	0	0	1

Interpretation:
BoFlex is telling you that it started observing <host=x.x.x.x> at <observation_start=1330437615.441414> and logged this record at <ts=1330440985.389741>. During this period (<ts - observation_start>), it saw <scan=0> <exploit=2> <egg_download=0> <cnc=0> <attack=1> events. The condition used to generate this record was <rule_id=condition2> (you can specifiy/ look at others in the function evaluate() in /usr/local/bro/share/bro/site/botflex/detection/correlation/correlation.bro).

Given this information, you might want to take a look at log files associated with exploit, and attack for host=x.x.x.x

The following summarizes which log files are generates for which 'class' of suspicious events:

Inbound Scan
-------------
botflexscan_log_ib.log

Exploit
-----------
exploit.log

Egg Download
-------------
egg.log

CnC
-------------
cnc.log

Attack
-------------
spam.log
sqli.log
botflexscan_log_ob.log

=====================================================
What we don't do:
=====================================================

BotFlex is not good (read: sucks) at the following:

--> Does not work on clusters at the moment (though it's on the menu and should happen soon!)
--> Does not do Snort style signature based detection (no *Rules* :-))

====================================================
End note:
====================================================

That's all folks. I welcome your questions / feedback 
-Sheharbano (sheharbano.k@gmail.com).




