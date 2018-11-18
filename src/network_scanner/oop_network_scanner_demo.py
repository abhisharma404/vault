#! /usr/bin/python

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import time


class PortScanner(object):

    def __init__(self, start_port=None, end_port=None, url=None, flags=None):
        if start_port is None:
            self.start_port = 0
        else:
            self.start_port = start_port

        if end_port is None:
            self.end_port = 65535
        else:
            self.end_port = end_port

        if url is None:
            print('[!] URL is empty, please specify an URL...')
        else:
            self.url = url

        self.flags = flags

        self.list_scans = ['fin','xmas']

    def fin_scan(self):
        key_values = {

            'scan_flag' : 'F',
            'noneTypeMessage' : '[+] Open',
            'TCPLayerFlags' : ['RA'],
            'TCPLayer_Found' : '[-] Closed',
            'TCPLayerNotFound' : None,
            'ICMPLayerFound' : '[!] Filtered'

        }

        self.baseScan(dict_values=key_values)

    def null_scan(self):

        key_values = {

            'scan_flag': None,
            'noneTypeMessage' : '[+] Open',
            'TCPLayerFlags' : ['R', 'RA'],
            'TCPLayer_Found' : '[-] Closed',
            'TCPLayerNotFound' : None,
            'ICMPLayerFound' : '[!] Filtered'

        }

        self.baseScan(dict_values=key_values)

    def tcp_ack_scan(self):

        key_values = {

            'scan_flag' : 'A',
            'noneTypeMessage' : '[+] Filtered',
            'TCPLayerFlags' : ['R','RA'],
            'TCPLayer_Found' : '[-] Unfiltered',
            'TCPLayerNotFound' : None,
            'ICMPLayerFound' : '[!] Filtered'

        }

        self.baseScan(dict_values=key_values)

    def tcp_window_scan(self):

        key_values = {
            'scan_flag' : 'A',
            'noneTypeMessage' : '[-] Filtered',
            'TCPLayerFlags' : ['R', 'RA'],
            'TCP' : 'x'
        }

    def xmas_scan(self):

        key_values = {

            'scan_flag' : 'FPU',
            'noneTypeMessage' : '[+] Open',
            'TCPLayerFlags' : ['RA'],
            'TCPLayer_Found' : '[-] Closed',
            'TCPLayerNotFound': '[-] ',
            'ICMPLayerFound' : '[!] Filtered'

        }

        self.threading_scan(dict_values=key_values)

    def craft_packet(self, dport, flag):
        ip_packet = IP(dst=self.url)
        tcp_packet = TCP(sport=1024, dport=dport, flags=flag)

        return ip_packet, tcp_packet

    def baseScan(self, dict_values, port):

        scan_flag = dict_values['scan_flag']
        noneTypeMessage = dict_values['noneTypeMessage']
        TCPLayerFlags = dict_values['TCPLayerFlags']
        TCPLayer_Found = dict_values['TCPLayer_Found']
        TCPLayerNotFound = dict_values['TCPLayerNotFound']
        ICMPLayerFound = dict_values['ICMPLayerFound']

        ip_packet, scan_packet = self.craft_packet(dport=port, flag=scan_flag)
        packet_resp = sr1(ip_packet/scan_packet, timeout=2, verbose=False)

        if (str(type(packet_resp))=="<class 'NoneType'>"):
            if noneTypeMessage == '[+] Open':
                print(str(noneTypeMessage) + ' -> ' + str(port))

        elif (packet_resp.haslayer(TCP)):
            if (packet_resp.getlayer(TCP).flags in TCPLayerFlags):
                # send_rst if tcp full scan
                if TCPLayer_Found == '[+] Open':
                    print(str(TCPLayer_Found) + ' -> ' + str(port))
            else:
                pass
                # or user defined message

        elif (packet_resp.haslayer(ICMP)):
            icmp_layer = packet_resp.getlayer(ICMP)
            if (int(icmp_layer.type)==3 and int(icmp_layer.code) in [1,2,3,9,10,13]):
                print(str(ICMPLayerFound) + ' -> ' + str(port))

    def threading_scan(self, dict_values):

        t1 = time.time()

        port_list = [port for port in range(0, 200)]

        dict_list = []

        for i in range(len(port_list)):
            dict_list.append(dict_values)

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(self.baseScan, dict_list, port_list)

        t2 = time.time()

        print('[+] The time taken is...', t2-t1)


if __name__ == '__main__':
    newObj = PortScanner(url='10.0.2.6')
    newObj.fin_scan()
    newObj.null_scan()
    newObj.tcp_ack_scan()
    newObj.xmas_scan()
