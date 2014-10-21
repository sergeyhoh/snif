import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up Scapy
from scapy.all import *
conf.verb = 0
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
from daemon import Daemon


def is_int_str(v):
    v = str(v).strip()
    return v == '0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()


class WifiSniffDaemon(Daemon):
    DEVNULL = open(os.devnull, 'w')

    # Define the interface name that we will be sniffing from
    INTERFACE = "wlan0"
    # Define tmp file for store mac-address info
    LOGFILE = "snifflog"
    # Save and upload intervals
    SAVE_INTERVAL = 600
    UPLOAD_INTERVAL = 900

    def __init__(self, pidfile):
        Daemon.__init__(self, pidfile)

        # Define last log save time
        # self.last_save_time = int(time.time())

        # List to keep track of client MAC addresses
        self.sniffclients = []
        self.sniffclients_info = []
        self.sniffinfo = {}

        self.monitor_on = self.is_monitor_on(self.INTERFACE)

    def packet_handler(self, pkt):
        # global last_save_time

        mgmt_type = 0   # management frame type
        # 3 management frame subtypes sent exclusively by clients
        mgmt_sub_types = 4

        # Make sure the packet has the Scapy Dot11 layer present
        if pkt.haslayer(Dot11):
            # Check to make sure this is a management frame (type=0) and that
            # the subtype is one of management frame subtypes indicating a
            # a wireless client
            if pkt.type == mgmt_type and pkt.subtype == mgmt_sub_types:
                self.collect_packet_info(pkt)

    def collect_packet_info(self, pkt):
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
        if sniffinfo.get(pkt.addr2) is None or (dtn - sniffinfo[pkt.addr2]).seconds < self.SAVE_INTERVAL+1:
            print "Source: %s SSID: %s RSSi: %d" % (
                pkt.addr2, pkt.getlayer(Dot11ProbeReq).info, signal_strength
            )
            sniffinfo[pkt.addr2] = dtn

    def save_sniff_log(self, file_name):
        global sniffinfo
        while 1:
            tmp_sniffinfo = sniffinfo
            sniffinfo = {}

            fn = file_name+'_'+datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            with open(fn, 'w') as f:
                for smac, stime in tmp_sniffinfo.items():
                    f.write("smac: %s; time: %s\n" % (smac, stime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))

            tmp_sniffinfo.clear()

            time.sleep(self.SAVE_INTERVAL)

    def setup_iface(self, interface):
        if not self.monitor_on:
            # Start monitor mode on a wireless INTERFACE
            print 'Start monitor mode on a wireless INTERFACE'
            return self.enable_mon_mode(interface)

    def is_monitor_on(self, interface):
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=self.DEVNULL)
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0:
                continue  # String isn't empty
            if line[0] != ' ':  # Line don't start with space
                if re.search('^(wlan[0-9])', line).group(1) == interface:
                    if 'Mode:Monitor' in line:
                        return True
                    else:
                        return False

    @staticmethod
    def hw_mac_addr(interface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

    @staticmethod
    def mac_hex2int(mac_hex):
        if re.search('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac_hex, re.IGNORECASE):
            return int(mac_hex.replace(':', ''), 16)
        else:
            return None

    @staticmethod
    def mac_int2hex(mac_int):
        if is_int_str(mac_int):
            mac_hex = '%012x' % mac_int
            return ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)])

    def enable_mon_mode(self, interface):
        print 'Starting monitor mode off '+interface
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            sys.exit('Could not start monitor mode')

    def disable_mon_mode(self, interface):
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode managed' % interface)
        os.system('ifconfig %s up' % interface)
        return iface

    def post_request(self, router_id, device_id, log_time):
        parse_url = "http://paynata.elasticbeanstalk.com/webapi/activities/activity"
        payload = {
            "beacon_mac": router_id,
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

    def get_request(self):
        parse_url = "http://paynata.elasticbeanstalk.com/webapi/activities/activity"
        headers = {
            'Content-Type': 'application/json'
        }
        r = requests.get(parse_url, headers=headers)

        if r.status_code == 200:
            return r.json()
        else:
            return None

    def upload_sniff_log(self, hw_mac):
        import glob

        while 1:
            for log_file in glob.glob('./snifflog_*'):
                if os.path.isfile(log_file) and (int(time.time()) - int(os.path.getctime(log_file))) > 60:
                    with open(log_file, 'r') as f:
                        for line in f:
                            match = re.search('^smac:\s(.*); time: (.*)$', line, re.IGNORECASE)
                            if match:
                                router_id = self.mac_hex2int(hw_mac)
                                device_id = self.mac_hex2int(match.group(1))
                                self.post_request(router_id, device_id, match.group(2))
                    os.remove(log_file)

            time.sleep(self.UPLOAD_INTERVAL)

    def stop_sniff(self, signal, frame):
        if self.monitor_on:
            # disable_mon_mode(INTERFACE)
            sys.exit('\nClosing')
        else:
            sys.exit('\nClosing')

    def run(self):
        hw_mac = self.hw_mac_addr(self.INTERFACE)
        # setup_iface(self.INTERFACE)

        # Start sniff log uploading
        upload = Thread(target=self.upload_sniff_log, args=(hw_mac,))
        upload.daemon = True
        upload.start()

        # Start files uploading
        save = Thread(target=self.save_sniff_log, args=(self.LOGFILE,))
        save.daemon = True
        save.start()

        # signal(SIGINT, self.stop_sniff)

        print "Starting scan at: %s" % datetime.now()
        print "Router MAC: %s" % hw_mac
        print "Monitor Mode: %s" % self.monitor_on
        sniff(iface=self.INTERFACE, prn=self.packet_handler, store=0, filter='type mgt subtype probe-req')


if __name__ == "__main__":
    if os.geteuid():
        sys.exit('You must run script under root')

    daemon = WifiSniffDaemon('/overlay/scripts/wifisniff.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)



