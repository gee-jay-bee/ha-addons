from scapy.all import *
from requests import post
from os import getenv
from json import load
from icmplib import multiping
from threading import Thread
from time import sleep
import logging

logger = logging.getLogger(__name__)

bearer = getenv('SUPERVISOR_TOKEN')
headers = { 
    "Authorization": "Bearer {}".format(bearer), 
    "content-type": "application/json" 
    }

EVENT_NAME_SEEN = 'dhcp_tracker_mac_seen'
EVENT_NAME_GONE = 'dhcp_tracker_mac_gone'

the_targets = None
device_tracking = None
create_device_trackers = False

with open('/data/options.json', 'r') as t:
    j = load(t)
    if 'mac_addresses' in j:
        the_targets = j['mac_addresses']
    if 'enable_device_tracker' in j:
        device_tracking = [] if j['enable_device_tracker'] else None
    if 'create_device_trackers' in j:
        create_device_trackers = j['create_device_trackers']

def tell_ha(url, data):
    try:
        post(url, headers=headers, json = data)
    except Exception as e:
        logger.exception(e)
        pass

def tell_ha_device_status(mac, status):
    if create_device_trackers:
        url = "http://supervisor/core/api/states/device_tracker.dhcp_tracked_{}".format(mac.replace(':', '_'))
        data = {
            "state": "home" if status else "not_home",
            "attributes": {
                "source_type": "dhcp_tracker"
            }
        }
        tell_ha(url, data)

def tell_ha_event_bus(event_name, mac, ip, host):
    url = "http://supervisor/core/api/events/{}".format(event_name) 
    data = {
        "mac": mac,
        "ip": ip,
        "host": host
    }
    logger.info('Sending {}: {}/{}'.format(event_name, mac, ip))
    tell_ha(url, data)


def device_tracker():
    global device_tracking

    currently_watching = {}
    while device_tracking is not None:
        # list of tuples: first element is mac, second element is ip
        for device in device_tracking:
            if device[1] in currently_watching:
                continue
            
            logger.debug('Adding {}'.format(device))
            # ping by IP, report to HA by mac
            currently_watching[device[1]] = device[0]
            tell_ha_device_status(device[0], True)
        
        device_tracking.clear()
        if len(currently_watching) > 0:
            #ignoring hostname as not really reliably known!
            logger.debug('Starting ping')
            hosts = multiping(currently_watching.keys(), count=1, timeout=1.0)
            logger.debug('Done')
            for host in hosts:
                if not host.is_alive:
                    mac = currently_watching[host.address]
                    logger.debug('Removing {}/{}'.format(mac, host.address))
                    tell_ha_device_status(mac, False)
                    tell_ha_event_bus(EVENT_NAME_GONE, mac, host.address, None)
                    del currently_watching[host.address]

        sleep(1)

def tell_device_tracker(mac, ip):
    if device_tracking is not None:
        logger.info('Tracking {}/{}'.format(mac, ip))
        device_tracking.append((mac, ip))

def dissect_dhcp(packet):
    mac = None
    ip = None
    host = None 

    if packet.haslayer(Ether):
        mac = packet.getlayer(Ether).src

    dhcp_options = packet[DHCP].options
    for item in dhcp_options:
        logger.debug('{} item found'.format(item))
        try:
            label, value = item
        except ValueError:
            continue
        if label == 'requested_addr':
            ip = value
        elif label == 'host':
            host = value.decode()

    if ip and mac and mac in the_targets:
        tell_ha_event_bus(EVENT_NAME_SEEN, mac, ip, host)
        tell_device_tracker(mac, ip)

if __name__ == "__main__":
    t = None
    if device_tracking is not None:
        t = Thread(target=device_tracker)
        t.start()
        
    sniff(prn=dissect_dhcp, filter='udp and (port 67 or port 68)')

    if t:
        device_tracking = None
        t.join()