#! /usr/bin/python

import time
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import colors
import os


class ARPScan(object):

    def __init__(self, ip, start_ip=None, end_ip=None, threads=None):

        self.is_root()

        if ip is None:
            colors.error('IP address cannot be none.')
            sys.exit(1)
        else:
            self.ip = ip

        if start_ip is None:
            self.start_ip = 0
        elif (int(start_ip) < 0 or int(start_ip) > 256):
            colors.error('Start range cannot be less than 0 or greater than '
                         '256')
            sys.exit(1)
        else:
            self.start_ip = int(start_ip)

        if end_ip is None:
            self.end_ip = 256
        elif (int(end_ip) > 256 or int(end_ip) < 0):
            colors.error('End range cannot be greater than 256 or less than 0')
            sys.exit(1)
        else:
            self.end_ip = int(end_ip)

        if threads is None:
            self.threads = 1
        else:
            self.threads = int(threads)

        self.answ_packets = []

    @staticmethod
    def is_root():
        """
        Checks if program is running as root or not
        """

        if os.geteuid() != 0:
            colors.error('Please run as root')
            sys.exit(1)
        else:
            colors.success('Running as root')

    def parseResult(self, t1):
        """
        Prints the live IP with their MAC address

        :t1: Start time of the scan
        """

        print('-' * 36)
        print('IP'.ljust(15, ' ') + '|' + '  MAC'.ljust(19, ' ') + '|')
        print('-' * 36)

        index = 1
        response_dict = {}

        for packets in self.answ_packets:

            for ele in packets:
                data = str(index) + '. ' + ele[1].psrc + ' : ' + ele[1].src
                response_dict[index] = [ele[1].psrc, ele[1].src]
                print(data.ljust(33, ' '), '|')
                print('-' * 35)
                index = index + 1

        t2 = time.time()
        colors.success('Completed in {}'.format(t2-t1))

        return index, response_dict

    def setIP(self):
        self.ip = self.ip.split('.')[0:3]
        self.ip = '.'.join(self.ip)

    def ARPScan(self, end):
        """
        Sends ARP Request packets to the destination IP

        :end: End part of the IP
        """

        arp_ip = self.ip + '.' + str(end)
        print('Scanning : {}'.format(arp_ip), end='\r')
        sys.stdout.flush()
        arp_req = ARP(pdst=arp_ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_req_broad = broadcast/arp_req
        answ = srp(arp_req_broad, verbose=False, timeout=1)[0]
        if answ:
            self.answ_packets.append(answ)

    def threadingScan(self):
        """
        Threads the scanning process
        """

        t1 = time.time()

        self.setIP()

        colors.info('ARP Scan started...')

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for ip in range(self.start_ip, self.end_ip):
                task = executor.submit(self.ARPScan, (ip))
                tasks.append(task)

        index, response_dict = self.parseResult(t1)
        return index, response_dict
