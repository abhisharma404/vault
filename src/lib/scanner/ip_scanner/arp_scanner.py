#! /usr/bin/python

import time
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import colors
from vault_cli import errors
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
        else:
            try:
                start_ip = int(start_ip)
            except (ValueError, TypeError):
                errors.report_error('Invalid start IP range', code='E1002',
                                    hint='Provide a numeric start range.')
                sys.exit(1)
            if start_ip < 0 or start_ip > 256:
                errors.report_error('Start range cannot be less than 0 or '
                                    'greater than 256', code='E1002')
                sys.exit(1)
            self.start_ip = start_ip

        if end_ip is None:
            self.end_ip = 256
        else:
            try:
                end_ip = int(end_ip)
            except (ValueError, TypeError):
                errors.report_error('Invalid end IP range', code='E1002',
                                    hint='Provide a numeric end range.')
                sys.exit(1)
            if end_ip > 256 or end_ip < 0:
                errors.report_error('End range cannot be greater than 256 or '
                                    'less than 0', code='E1002')
                sys.exit(1)
            self.end_ip = end_ip

        if threads is None:
            self.threads = 1
        else:
            try:
                self.threads = int(threads)
            except (ValueError, TypeError):
                errors.report_error('Invalid number of threads',
                                    code='E1011',
                                    hint='Provide a numeric thread count.')
                sys.exit(1)

        self.answ_packets = []

    @staticmethod
    def is_root():
        """
        Checks if program is running as root or not
        """

        if os.geteuid() != 0:
            colors.error('Please run as root')
            errors.report_error('Please run as root', code='E5001',
                                hint='Run with sudo/root.')
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
        try:
            answ = srp(arp_req_broad, verbose=False, timeout=1)[0]
        except Exception as e:
            errors.report_error('ARP scan failed for {}'
                                .format(arp_ip), exc=e, code='E3001')
            return
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
