##!/bin/bash 

prefix="/media/pp/ROC_data/"

mkdir  $prefix"stats"

ls --ignore-backups |
egrep '\.' | 
while read line; do echo $line; python $prefix"roc_data.py" $prefix"malicious.txt" $prefix"benign.txt" $line $prefix"stats/stats_"$line; done

rm "tp.txt"
rm "tn.txt"
rm "fp.txt"
rm "fn.txt"

cd "scan/ib"
ls --ignore-backups |
egrep '\.' | 
while read line; do echo $line; python $prefix"roc_data.py" $prefix"malicious.txt" $prefix"benign.txt" $line $prefix"stats/stats_"$line; done	
rm "tp.txt"
rm "tn.txt"
rm "fp.txt"
rm "fn.txt"

cd "../ob"
ls --ignore-backups |
egrep '\.' | 
while read line; do echo $line; python $prefix"roc_data.py" $prefix"malicious.txt" $prefix"benign.txt" $line $prefix"stats/stats_"$line; done
rm "tp.txt"
rm "tn.txt"
rm "fp.txt"
rm "fn.txt"



