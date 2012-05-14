#!/usr/bin/env python

#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////#
#										 				  #
# 		This script compares a data file (A) with a groundtruth data file (B)				  #
#		of 'Bad' entities and another file (C) with 'Benign' entities to calculate			  #
#		True Positives (A intersection B), False Positives (A - True Positives),True 			  #
#		Negatives (C - (A intersection C)) and False Negatives (B - (A intersection B)).		  #
#		The hosts corresponding to TP,TN,FP,FN are printed out to similar named files			  #
#												 		  #
#		Usage: <progname> InFile1 InFile2 InFile3 OutFile						  #
#			InFile1: File of known bad entities					         	  #
#			InFile2: File of known bengin/good entities						  #
#			InFile3: File for which TP,TN,FP,FN need to be calculated				  #
#			OutFile: Output file									  #
#														  #
#		Input file format: Each line in file represents an entity					  #
# 							 							  #
# 		by Sheharbano on Sat May 12 13:38:30 PKT 2012   		  				  #
#										 				  #
#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////#


import re
import sys
import os

class ROCDataGenerator(object):
	def __init__(self, infile1, infile2, infile3, outfile):
    		self._file_bad = infile1
		self._file_good = infile2
		self._file_bad_tagged = infile3
		self._file_output = outfile

		# tables to maintain the good, bad and bad_tagged entities read
		# from corresponding files
    		self._dict_good = {}
		self._dict_bad = {}
		self._dict_bad_tagged = {}

		# table to hold entities from _dict_bad_tagged that matched with good entities (TN)
		self._dict_bad_tagged_tn = {}
  		# table to hold entities from _dict_bad_tagged that matched with bad entities (TP)
		self._dict_bad_tagged_tp = {}
		# table to hold entities from _dict_bad_tagged that classified bad entities as good (FN)
		self._dict_bad_tagged_fn = {}
		# table to hold entities from _dict_bad_tagged that classified good entities as bad (FP)
		self._dict_bad_tagged_fp = {}

  	def start(self):
    		self.read_files()

		# calculating TP and FP
		for element in self._dict_bad_tagged:		
			# bad_tagged intersection bad	
 			if element in self._dict_bad:
				self._dict_bad_tagged_tp[element] = 0;
			# bad_tagged - (bad_tagged intersection bad)	
 			else:
				self._dict_bad_tagged_fp[element] = 0;

		# calculating FN
		for element in self._dict_bad:
			if not(element in self._dict_bad_tagged):
				self._dict_bad_tagged_fn[element] = 0;

		# calculating TN
		for element in self._dict_good:
			if not(element in self._dict_bad_tagged):
				self._dict_bad_tagged_tn[element] = 0;
	

	def read_files(self):
		f = open(self._file_good, 'r')
		for line in f:
			self._dict_good[line.strip()] = 0
		f.close()
								
		f = open(self._file_bad, 'r')
		for line in f:
			self._dict_bad[line.strip()] = 0
		f.close()

		f = open(self._file_bad_tagged, 'r')
		for line in f:
			self._dict_bad_tagged[line.strip()] = 0
		f.close()	


  	def print_stats(self):
		# Print high order stats to output file
		f = open(self._file_output, 'w')

		total_hosts = len(self._dict_bad)+len(self._dict_good)
		total_good = len(self._dict_good)
		total_bad = len(self._dict_bad)
		fp = len(self._dict_bad_tagged_fp)
		fn = len(self._dict_bad_tagged_fn)
		tp = len(self._dict_bad_tagged_tp)
		tn = len(self._dict_bad_tagged_tn)
		
		f.write("Total hosts: %d\n" %( total_hosts ))
		f.write("Number of known good/benign hosts: %d\n" %( total_good ) )
		f.write("Number of known bad/malicious hosts: %d\n\n" %( total_bad ))
		f.write("TP: %d\tFP: %d\tTN: %d\tFN: %d\n\n" %( tp, fp, tn, fn ))
		f.write("Detection/TP rate: %f\n" %( (tp/float(total_bad))*100 ))
		f.write("Miss/FP rate: %f\n" %( (fp/float(total_good))*100 ))

		f.close()

		# Write hosts classified as TP, TN, FP, FN 
		f = open("tp.txt", 'w')
		for element in self._dict_bad_tagged_tp:
			f.write("%s\n" % (element) )
		f.close()

		f = open("fp.txt", 'w')
		for element in self._dict_bad_tagged_fp:
			f.write("%s\n" % (element) )
		f.close()	

		f = open("tn.txt", 'w')
		for element in self._dict_bad_tagged_tn:
			f.write("%s\n" % (element) )
		f.close()

		f = open("fn.txt", 'w')
		for element in self._dict_bad_tagged_fn:
			f.write("%s\n" % (element) )
		f.close()
				

if __name__ == "__main__":
	if len(sys.argv) < 4:
    		print "usage: %s bad_file good_file file_to_check outfile" % (sys.argv[0])
    		sys.exit(1)
  	else:
		if not(os.path.exists(sys.argv[1])):
			print "The bad (first) file does not exist!"
			sys.exit(1)
		if not(os.path.exists(sys.argv[2])):
			print "The good (second) file does not exist!"
			sys.exit(1)
		if not(os.path.exists(sys.argv[3])):
			print "The file to check (third) does not exist!"
			sys.exit(1)

 	generator = ROCDataGenerator(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
  	generator.start()
  	generator.print_stats()

