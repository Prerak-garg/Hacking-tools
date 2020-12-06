#!/unr/bin/env python
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
    option = parser.parse_args()
    return option

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    aro_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(aro_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answer_list:
        clienr_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(clienr_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

option = get_arguments()
scan_result = scan(option.target)
print_result(scan_result)