import sys
import re

def spaceMemoryUsed(lines_file):
	pass

def get_list_from_file(fileName):
	fileToElaborate = list()
	f = open(fileName)
	lines = f.readlines()
	for line in lines:
		line.strip("\n")
		fileToElaborate.append(list(re.findall(r'\[([^]]*)\]',line)))
	f.close()
	return fileToElaborate

def get_JSON_str_from_file(fileName):
	fileToElaborate = "["
	f = open(fileName)
	lines = f.readlines()
	f.close()
	numElements = len(lines)
	counter = 0
	for line in lines:
		if counter != (numElements-1):
			fileToElaborate += line + ","
		else:
			fileToElaborate += line
		counter = counter + 1
	fileToElaborate += "]"
	return fileToElaborate

#In base of the file format you have to use one of these commands:
#python elaborateSimulations.py -p mega_adk/test01_timing.txt => with file to parsing
#or
#python elaborateSimulations.py -j mega_adk/json_test01_timing.txt => with file containing json objects
if __name__ == "__main__":
	if len(sys.argv) > 1:
		if sys.argv[1] == "-p":
			lines_file = get_list_from_file(sys.argv[2])
		elif sys.argv[1] == "-j":
			lines_file = get_JSON_str_from_file(sys.argv[2])
		print lines_file
	else:
		print "Error! set a file name to read"