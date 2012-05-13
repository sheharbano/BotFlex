#!/bin/bash

echo "Starting"
crontab -l > tmpcron
echo "1 * * * * ~/usr/local/bro/share/bro/site/botflex/blacklist_service.sh " >> tmpcron
crontab tmpcron
rm tmpcron
