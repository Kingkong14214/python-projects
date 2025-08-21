#!/usr/bin/python

import socket
import  os 
import  sys

def bannerscan(ip, port):
	try:
		socket.setdefaulttimeout(1)
		s=socket.socket()
		s.connect((ip, port))
		banner=s.recv(1024)
		return banner
	except:
		return
def checkvulns(banner, filename):
	f=open(filename, "r")
	for line in f.readlines():
		if  line.strip("\n") in banner:
			print ('[+]Server is vulnerable:{banner.strip()}')
def main():
	if len(sys.argv)==2:
		filename=sys.argv[1]
		if not  os.path.isfile(filename):
			print('[+]File does not exist!')
			exit(0)
		if not os.access(filename, os.R_OK):
			print ('[+]Access Denied!')
			exit(0)
	else:
		print(f'usage:{sys.argv[0] <vuln filename>}')
		exit(0)
	portlist =[21,22,25,80,110,443,445]
	for x in range (1,255):
		ip='192.168.199.{x}'
	for port in portlist:
		banner=bannerscan(port, ip)
		if banner:
			print(f'[+]{ip}/{port}: {banner.strip()}')
			checkvulns(banner, filename)
main()