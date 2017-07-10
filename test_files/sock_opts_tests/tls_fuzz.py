import socket
import sys
import subprocess
from random import randint

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_pass_fail(status):
	if status:
		print (bcolors.OKBLUE + "\tPassed!" + bcolors.ENDC)
	else:
		print (bcolors.FAIL + "\tFailed..." + bcolors.ENDC)
	

def gen_host_name_by_len(size):
	hn = ''
	if size < 1: return hn
	for j in range(size):
		hn += chr(randint(97,122))
	return hn

def host_name_len_eval(length, output):
	err_code = int(output.split(' ')[-1])
	if length >= 0 and length <= 255:
		if err_code == 0:
			return True
		if err_code != 0:
			return False
	if length < 0 or length > 255:
		if err_code == 0:
			return False
		if err_code != 0:
			return True 

def mismatched_eval(input_length, actual_length, output):
	err_code = int(output.split(' ')[-1])
	if input_length == actual_length:
		if err_code == 0:
			return True
		else:
			return False
	else:
		if err_code == 0:
			return False
		else:
			return True

def valid_char_eval(c):
	if ((c >= 48 and c <=57) or c == 45 or c == 46 or (c >= 65 and c <= 90) or (c >= 97 and c <= 122)):
		return True
	return False

def std_charset_test():
	# start host_name standard charset input test
	print("Starting standard charset test:"),
	sys.stdout.flush()
	pass_std_charset_test = True
	for i in range(32, 126 + 1): # +1 to include 126
		p = subprocess.Popen(['./tls_set_fuzz', 'localhost', chr(i), '1'], stdout=subprocess.PIPE)
		a = int(p.stdout.read().split()[-1]) 
		b = valid_char_eval(i)
		if ((a == 0 and not b) or (a != 0 and b)):
			pass_std_charset_test = False
			break
	print_pass_fail(pass_std_charset_test)

def ext_charset_test():
	# start host_name extended charset input test
	print("Starting extended charset test:"),
	sys.stdout.flush()
	pass_ext_charset_test = True
	for i in range(128, 255 + 1): # +1 to include 255
		p = subprocess.Popen(['./tls_set_fuzz', 'localhost', chr(i), '1'], stdout=subprocess.PIPE)
		if int(p.stdout.read().split()[-1]) == 0:
			pass_ext_charset_test = False
			break
	print_pass_fail(pass_ext_charset_test)

def host_name_length_test():
	# start host_name length test
	print("Starting host name length test:\t"),
	sys.stdout.flush()
	pass_len_test = True
	for i in range (-1000, 1000):
		hn = gen_host_name_by_len(i)
		p = subprocess.Popen(['./tls_set_fuzz', 'localhost', hn, str(i)], stdout=subprocess.PIPE)
		if not host_name_len_eval(i, p.stdout.read()):
			pass_len_test = False
			break	
	print_pass_fail(pass_len_test)

def mismatched_length_test():
	# start mismatched length test
	print("Starting mismatched length test:"),
	sys.stdout.flush()
	pass_mismatched_len = True
	for i in range (-1000, 1000):
		hn = "www.google.com"
		p = subprocess.Popen(['./tls_set_fuzz', 'localhost', hn, str(i)], stdout=subprocess.PIPE)	
		if not mismatched_eval(i, len(hn), p.stdout.read()):
			pass_mismatched_len = False
			break
	print_pass_fail(pass_mismatched_len)


#---------------------------------- START TESTS ----------------------------------------#

def main():
	std_charset_test()
	ext_charset_test()
	host_name_length_test()
	mismatched_length_test()

main()

