import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up Scapy
from scapy.all import *
conf.verb = 0  # Scapy I thought I told you to shut up
import os
import re
import sys
import time
from datetime import datetime
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import socket
import struct
import fcntl
import requests
import json

# Define the interface name that we will be sniffing from
interface = "wlan0"
# Define tmp file for store mac-address info
logfile = "snifflog"
# Define last log save time
# last_save_time = int(time.time())

# List to keep track of client MAC addresses
sniffclients = []
sniffclients_info = []

sniffinfo = {}
save_interal = 60
upload_interal = 90


def packet_handler(pkt):
    # global last_save_time

    mgmt_type = 0   # managment frame type
    # 3 management frame subtypes sent exclusively by clients
    mgmt_sub_types = 4

    # Make sure the packet has the Scapy Dot11 layer present
    if pkt.haslayer(Dot11):
        # Check to make sure this is a management frame (type=0) and that
        # the subtype is one of management frame subtypes indicating a
        # a wireless client
        if pkt.type == mgmt_type and pkt.subtype == mgmt_sub_types:
            collect_packet_info(pkt)


def collect_packet_info(pkt):
    # Probe Request Captured
    try:
        extra = pkt.notdecoded
    except:
        extra = None

    if extra is not None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100

    # Store observed client info
    dtn = datetime.now()
    if sniffinfo.get(pkt.addr2) is None or (dtn - sniffinfo[pkt.addr2]).seconds < save_interal+1:
        print "Source: %s SSID: %s RSSi: %d" % (
            pkt.addr2, pkt.getlayer(Dot11ProbeReq).info, signal_strength
        )
        sniffinfo[pkt.addr2] = dtn


def save_sniff_log(file_name):
    global sniffinfo
    while 1:
        tmp_snifinfo = sniffinfo
        sniffinfo = {}

        fn = file_name+'_'+datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with open(fn, 'w') as f:
            for smac, stime in tmp_snifinfo.items():
                f.write("smac: %s; time: %s\n" % (smac, timestamp(stime)))

        tmp_snifinfo.clear()

        time.sleep(save_interal)


def setup_iface(iface):
    if not monitor_on:
        # Start monitor mode on a wireless interface
        print 'Start monitor mode on a wireless interface'
        monmode = enable_mon_mode(iface)
        return monmode


def is_monitor_on(iface):
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DEVNULL)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0:
            continue  # String isn't empty
        if line[0] != ' ':  # Line dosn't start with space
            if re.search('^(wlan[0-9])', line).group(1) == iface:
                if 'Mode:Monitor' in line:
                    return True
                else:
                    return False


def is_int_str(v):
    v = str(v).strip()
    return v == '0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()


def hw_mac_addr(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', iface[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


def mac_hex2int(mac_hex):
    if re.search('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac_hex, re.IGNORECASE):
        return int(mac_hex.replace(':', ''), 16)
    else:
        return None


def mac_int2hex(mac_int):
    if is_int_str(mac_int):
        mac_hex = '%012x' % mac_int
        return ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)])


def timestamp(date):
    return int(time.mktime(date.timetuple()))


def enable_mon_mode(iface):
    print 'Starting monitor mode off '+iface
    try:
        os.system('ifconfig %s down' % iface)
        os.system('iwconfig %s mode monitor' % iface)
        os.system('ifconfig %s up' % iface)
        return iface
    except Exception:
        sys.exit('Could not start monitor mode')


def disable_mon_mode(iface):
    os.system('ifconfig %s down' % iface)
    os.system('iwconfig %s mode managed' % iface)
    os.system('ifconfig %s up' % iface)
    return iface


def post_request(router_id, device_id, log_time):
    parse_url = "http://paynata.elasticbeanstalk.com/webapi/activities/activity"
    payload = {
        "beacon_mac": 27,
        "client_mac": device_id,
        "timestamp": log_time
    }
    headers = {
        'Content-Type': 'application/json'
    }
    r = requests.post(parse_url, data=json.dumps(payload), headers=headers)

    if r.status_code == 200 or r.status_code == 201:
        return True
    else:
        return False


def get_request():
    parse_url = "http://paynata.elasticbeanstalk.com/webapi/activities/activity"
    headers = {
        'Content-Type': 'application/json'
    }
    r = requests.get(parse_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        return None


def upload_sniff_log(hw_mac):
    import glob

    while 1:
        for log_file in glob.glob('./snifflog_*'):
            if(os.path.isfile(log_file) and (int(time.time()) - int(os.path.getctime(log_file))) > 60):
                with open(log_file, 'r') as f:
                    for line in f:
                        match = re.search('^smac:\s(.*); time: (.*)$', line, re.IGNORECASE)
                        if match:
                            router_id = mac_hex2int(hw_mac)
                            device_id = mac_hex2int(match.group(1))
                            print(router_id, device_id, match.group(2))
                            post_request(router_id, device_id, match.group(2))
                os.remove(log_file)

        time.sleep(upload_interal)


def stop(signal, frame):
    if monitor_on:
        # disable_mon_mode(interface)
        sys.exit('\nClosing')
    else:
        sys.exit('\nClosing')


def main():
    global DEVNULL, hw_mac, monitor_on
    DEVNULL = open(os.devnull, 'w')
    hw_mac = hw_mac_addr(interface)
    monitor_on = is_monitor_on(interface)
    # setup_iface(interface)

    # Start sniff log uploading
    upload = Thread(target=upload_sniff_log, args=(hw_mac,))
    upload.daemon = True
    upload.start()

    # Start files uploading
    saveing = Thread(target=save_sniff_log, args=(logfile,))
    saveing.daemon = True
    saveing.start()

    signal(SIGINT, stop)

    print "Starting scan at: %s" % datetime.now()
    print "Router MAC: %s" % hw_mac
    print "Monitor Mode: %s" % monitor_on
    sniff(iface=interface, prn=packet_handler, store=0, filter='type mgt subtype probe-req')

if __name__ == "__main__":
    if os.geteuid():
        sys.exit('You must run script under root')

    main()
