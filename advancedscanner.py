#!/usr/bin/python

from socket import *
import optparse
from threading import *

def connScan(tgthost, tgtport):
	sock=socket(AF_INET, SOCK_STREAM)
	sock.connect(tgthost, tgtport)
	try:print('[+]%d is open', % tgtport)
	except:print('[+]%d is closed',% tgtport)
	finally:sock.close()

def  portscanner(tgthost, tgtports):
	try:
		tgtip=gethostbyname(tgthost)
	except:
		print('unknown host', %tgthost)
	try:
		tgtname=gethostbyaddr(tgtip)
		print('[+]scan results for' +tgtname[0])
	except:
		print('[+]scan results for' +tgtip
	setdefaulttimeout(1)
	for  tgtport in tgrports:
		t=Thread(target=connScan, args(tgthost, int(tgtports)))
		t.start()
def main():
	parse=optparse.OptionParser('usage of the program: ' + '-H<target host> -p<target port>')
	parser.add_option('-H', dest='tgthost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtport', type='string', help='specify target port seperated by comma')
	(options, args)=parse.parse_args()

	tgthost=options.tgthost
	tgtports=str(options.tgtport)split.(',')
	if (tgthost==None | (tgtport(0)==None):
		print parse.usage
		exit(0)

if__name__=='__main__':
	main()
