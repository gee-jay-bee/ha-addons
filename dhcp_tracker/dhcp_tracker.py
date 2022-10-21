from scapy.all import *
from requests import post
from os import getenv
from json import load

bearer = getenv('SUPERVISOR_TOKEN')
EVENT_NAME = 'dhcp_tracker_mac_seen'

with open('/data/options.json', 'r') as t:
    the_targets = load(t)['mac_addresses']

def dissect_dhcp(packet):
    mac = None
    ip = None
    host = None

    if packet.haslayer(Ether):
        mac = packet.getlayer(Ether).src

    dhcp_options = packet[DHCP].options
    for item in dhcp_options:
        try:
            label, value = item
        except ValueError:
            continue
        if label == 'requested_addr':
            ip = value
        elif label == 'host':
            host = value.decode()

    if ip and mac and mac in the_targets:
        url = "http://supervisor/core/api/events/{}".format(EVENT_NAME) 
        headers = { 
            "Authorization": "Bearer {}".format(bearer), 
            "content-type": "application/json" 
            }
        data = {
            "mac": mac,
            "ip": ip,
            "host": host
        }
        response = post(url, headers=headers, json = data)

if __name__ == "__main__":
    sniff(prn=dissect_dhcp, filter='udp and (port 67 or port 68)')