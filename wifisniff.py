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


DEVNULL = open(os.devnull, 'w')
MAIN_DIR = os.path.dirname(os.path.realpath(__file__))
CONF_FILE = "wifisniff_conf.yml"
LOG_FILE = "wifisniff.log"
PID_FILE = "wifisniff.pid"


def is_int_str(v):
    v = str(v).strip()
    return v == '0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()


def timestamp(date):
    return int(time.mktime(date.timetuple()))


class WifiSniffLogging:
    def __init__(self):
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        # create console handler and set level to info
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # create error file handler and set level to error
        handler = logging.FileHandler(os.path.join(MAIN_DIR, LOG_FILE), "w", encoding=None, delay="true")
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # create debug file handler and set level to debug
        handler = logging.FileHandler(os.path.join(MAIN_DIR, LOG_FILE), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def wifisniff_logger(self):
        return self.logger


class WifiSniffDaemon(Daemon):
    # Define the interface name that we will be sniffing from
    INTERFACE = "wlan0"
    # Define tmp file for store mac-address info
    LOGGING_NAME = "snifflog"
    # Save and upload intervals
    SAVE_INTERVAL = 600
    SEND_INTERVAL = 900

    def __init__(self, pidfile):
        Daemon.__init__(self, pidfile)

        # Init logger
        self.logger = WifiSniffLogging().wifisniff_logger()
        # List to keep track of client MAC addresses
        self.sniffclients = []
        self.sniffclients_info = []
        self.sniffinfo = {}
        self.day_sniffinfo = {}
        # Main settings
        self.interface = self.INTERFACE
        self.save_interval = self.SAVE_INTERVAL
        self.send_interval = self.SEND_INTERVAL
        # Upload settings
        self.beacon_mac, self.post_url, self.get_url = None, None, None
        # WiFi settings
        self.ssid, self.ssid_key = None, None
        # self.ip_type, self.ip_add, self.ip_mask, self.ip_gtw, self.ip_dns = None, None, None, None, None
        # Load configs from yml file
        self.load_config()

        self.monitor_on = self.is_monitor_on()

    def load_config(self):
        """
        Load config from yml file if exist, and reinitialize some variables
        :return:
        """
        conf_location = "%s/%s" % (MAIN_DIR, CONF_FILE)
        if os.path.isfile(conf_location):
            import yaml
            try:
                stream = open(conf_location, 'r')
                settings = yaml.load(stream).get('wifisniff')

                if settings is not None:
                    self.beacon_mac = settings.get('beacon_mac')
                    self.post_url = settings.get('post_url')
                    self.get_url = settings.get('get_url')
                    self.interface = settings.get('interface')
                    self.save_interval = settings.get('save_interval')
                    self.send_interval = settings.get('send_interval')
                    self.ssid = settings.get('ssid')
                    self.ssid_key = settings.get('ssid_key')

                    # ipconf = settings.get('ipconf')
                    # if ipconf is not None:
                    #     self.ip_type = ipconf.get('type')
                    #     self.ip_add = ipconf.get('ip')
                    #     self.ip_mask = ipconf.get('mask')
                    #     self.ip_gtw = ipconf.get('gateway')
                    #     self.ip_dns = ipconf.get('dns')
            except yaml.YAMLError, exc:
                self.logger.error("Error in configuration file:", exc)
                if hasattr(exc, 'problem_mark'):
                    mark = exc.problem_mark
                    self.logger.error("Error position: (%s:%s)" % (mark.line+1, mark.column+1))

    def packet_handler(self, pkt):
        # global last_save_time

        mgmt_type = 0  # management frame type
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
            signal_strength = -(256 - ord(extra[-4:-3]))
        else:
            signal_strength = -100

        # Store observed client info
        dtn = datetime.now()
        if self.day_sniffinfo.get(pkt.addr2) is None or self.day_sniffinfo[pkt.addr2].date() < datetime.today().date():
            self.logger.info("Source: %s SSID: %s RSSi: %d Time: %s" % (
                pkt.addr2, pkt.getlayer(Dot11ProbeReq).info,
                signal_strength,
                datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ))
            self.sniffinfo[pkt.addr2] = dtn
            self.day_sniffinfo[pkt.addr2] = dtn

    def save_sniff_log(self):
        """
        Save logged mac address to file
        :return:
        """
        while 1:
            tmp_sniffinfo = self.sniffinfo

            self.sniffinfo = {}
            self.day_sniffinfo = {key: value for key, value in self.day_sniffinfo.items() if
                                  value.date() == datetime.today().date()}

            fn = "%s/%s_%s" % (MAIN_DIR, self.LOGGING_NAME, datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
            with open(fn, 'w') as f:
                for smac, stime in tmp_sniffinfo.items():
                    f.write("smac: %s; time: %s\n" % (smac, timestamp(stime)))

            tmp_sniffinfo.clear()

            time.sleep(self.SAVE_INTERVAL)

    def upload_sniff_log(self, hw_mac):
        """
        Upload sniffed info to remote server every self.send_interval seconds
        :param hw_mac:
        :return:
        """
        import glob

        while 1:
            # Turn wifi device to Station (STA) mode
            if self.is_monitor_on():
                self.disable_mon_mode()
                time.sleep(10)
            # If device connected to internet send log info
            if self.is_connected():
                for log_file in glob.glob("%s/%s_*" % (MAIN_DIR, self.LOGGING_NAME)):
                    if os.path.isfile(log_file) and (int(time.time()) - int(os.path.getctime(log_file))) > 60:
                        with open(log_file, 'r') as f:
                            for line in f:
                                match = re.search('^smac:\s(.*); time: (.*)$', line, re.IGNORECASE)
                                if match:
                                    router_id = self.mac_hex2int(hw_mac)
                                    device_id = self.mac_hex2int(match.group(1))
                                    self.post_request(self.beacon_mac, device_id, match.group(2))
                        os.remove(log_file)
            # Turn wifi device to Monitor mode
            if not self.is_monitor_on():
                self.enable_mon_mode()

            time.sleep(self.send_interval)

    def is_monitor_on(self):
        """
        Check if wifi interface in monitor mode
        :return:
        """
        proc = Popen(["iwconfig %s" % self.interface], stdout=PIPE, stderr=DEVNULL)
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0:
                continue  # String isn't empty
            if line[0] != ' ':  # Line don't start with space
                if re.search('^(\w+)\s\.*(?:Mode:Monitor)', line).group(1) == self.interface:
                    return True
                else:
                    return False

    @staticmethod
    def hw_mac_addr(iface_name):
        """
        Detect interface mac address
        :param iface_name:
        :return:
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface_name[:15]))
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

    @staticmethod
    def mac_hex2int(mac_hex):
        """
        Convert hexadecimal mac notation to integer
        :param mac_hex:
        :return:
        """
        if re.search('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac_hex, re.IGNORECASE):
            return int(mac_hex.replace(':', ''), 16)
        else:
            return None

    @staticmethod
    def mac_int2hex(mac_int):
        """
        Convert integer mac notation to hexadecimal
        :param mac_int:
        :return:
        """
        if is_int_str(mac_int):
            mac_hex = '%012x' % mac_int
            return ':'.join([mac_hex[i:i + 2] for i in range(0, 12, 2)])

    @staticmethod
    def is_connected():
        try:
            # see if we can resolve the host name -- tells us if there is
            # a DNS listening
            host = socket.gethostbyname('www.google.com')
            # connect to the host -- tells us if the host is actually reachable
            socket.create_connection((host, 80), 2)
            return True
        except:
            pass
        return False

    def enable_mon_mode(self):
        """
        Turn off Station (STA) mode on wifi adapter, and turn on Monitor mode
        :return:
        """
        match = re.search('^([a-z]+)([0-9]+)$', self.interface, re.IGNORECASE)
        if match:
            try:
                iface_num = match.group(2)

                os.system('uci del wireless.@wifi-iface[%s].ssid' % iface_num)
                os.system('uci del wireless.@wifi-iface[%s].key' % iface_num)
                os.system('uci del wireless.@wifi-iface[%s].encryption' % iface_num)
                os.system('uci set wireless.@wifi-iface[%s].mode=monitor' % iface_num)
                os.system('uci set wireless.@wifi-iface[%s].hidden=1' % iface_num)
                os.system('uci commit wireless')
                os.system('wifi')
            except Exception, exc:
                self.logger.error('Could not start monitor mode', exc)
                sys.exit('Could not start monitor mode')

    def disable_mon_mode(self):
        """
        Turn off Monitor mode on wifi adapter, and turn on Station (STA) mode
        :return:
        """
        match = re.search('^([a-z]+)([0-9]+)$', self.interface, re.IGNORECASE)
        if match and self.ssid is not None and self.ssid_key is not None:
            try:
                iface_num = match.group(2)

                os.system('uci del wireless.@wifi-iface[%s].hidden' % iface_num)
                os.system('uci set wireless.@wifi-iface[%s].mode=sta' % iface_num)
                os.system('uci set wireless.@wifi-iface[%s].ssid=%s' % (iface_num, self.ssid))
                os.system('uci set wireless.@wifi-iface[%s].encryption=psk2' % iface_num)
                os.system('uci set wireless.@wifi-iface[%s].key=%s' % (iface_num, self.ssid_key))
                os.system('uci commit wireless')
                os.system('wifi')
            except Exception, exc:
                self.logger.error('Could not off monitor mode', exc)
                sys.exit('Could not off monitor mode')

    def post_request(self, router_id, device_id, log_time):
        """
        Send sniffed mac address to remote server
        :param router_id:
        :param device_id:
        :param log_time:
        :return:
        """
        if not self.post_url:
            return False

        payload = {
            "beacon_mac": router_id,
            "client_mac": device_id,
            "timestamp": log_time
        }
        headers = {
            'Content-Type': 'application/json'
        }
        r = requests.post(self.post_url, data=json.dumps(payload), headers=headers)

        if r.status_code == 200 or r.status_code == 201:
            return True
        else:
            return False

    def get_request(self):
        """
        Get some info from remote server
        :return:
        """
        if not self.get_url:
            return False

        headers = {
            'Content-Type': 'application/json'
        }
        r = requests.get(self.get_url, headers=headers)

        if r.status_code == 200:
            return r.json()
        else:
            return None

    def run(self):
        self.logger.info('Start monitor mode on a wireless INTERFACE')
        self.enable_mon_mode()

        hw_mac = self.hw_mac_addr(self.interface)
        # Start sniff log uploading
        upload = Thread(target=self.upload_sniff_log, args=(hw_mac,))
        upload.daemon = True
        upload.start()

        # Start files uploading
        save = Thread(target=self.save_sniff_log)
        save.daemon = True
        save.start()

        self.logger.info("Starting scan at: %s" % datetime.now())
        self.logger.info("Router MAC: %s" % hw_mac)
        self.logger.info("Monitor Mode: %s" % self.monitor_on)
        sniff(iface=self.INTERFACE, prn=self.packet_handler, store=0, filter='type mgt subtype probe-req')


if __name__ == "__main__":
    if os.geteuid():
        sys.exit('You must run script under root')

    daemon = WifiSniffDaemon("%s/%s" % (MAIN_DIR, PID_FILE))
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
