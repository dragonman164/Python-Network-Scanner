#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Target IP/IP range")
    (options,arguments) = parser.parse_args()
    return options

def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    #scapy.ls(scapy.ARP()) 
    #scapy.ls(scapy.Ether())
    arp_request_broadcast = broadcast/arp_request
    #arp_request_broadcast.show()
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    #print(answered_list.summary())
    clients_list = []
    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------------")
    for client in result_list:
        print(client["ip"]+ "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)