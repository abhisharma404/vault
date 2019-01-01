#! /usr/bin/python

import subprocess
import re
import sys
import time
import random
import colors
import os


class MACChanger(object):

    def __init__(self, mac_addr=None, interface=None):

        self.is_root()

        if mac_addr is None:
            self.newMAC = self.generateMAC()
        elif self.validateMAC(mac_addr):
            self.newMAC = mac_addr
        else:
            colors.error('Please provide a valid MAC address...')
            sys.exit(1)

        colors.info('MAC address will be changed to : {}'.format(self.newMAC))

        if interface is None:
            self.interface = self.getInterface()
        else:
            self.interface = interface

        self.origMAC = self.interfaceMAC()

        colors.info('Original MAC address is : {}'.format(self.origMAC))

        if self.interface is None or \
           self.newMAC is None or \
           self.origMAC is None:
            colors.error('Error! could not change the MAC')
            sys.exit(1)

    @staticmethod
    def validateMAC(mac):
        """
        Check whether the input MAC is valid or not
        """

        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
            return True

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
    def generateMAC():
        """
        Generates random MAC address
        """

        colors.info('No desired MAC found, generating random MAC...')

        return "52:54:00:%02x:%02x:%02x" % (
                    random.randint(0, 255),
                    random.randint(0, 255),
                    random.randint(0, 255),
                    )

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
            intf = int(input('\n>> Enter the index of the interface : ').strip())

        colors.info('Selected interface is : {}'.format(interfaces[intf]))
        return interfaces[intf]

    def interfaceMAC(self):
        """
        Returns the MAC address of
        the selected interface
        """

        result = subprocess.Popen(['ifconfig', self.interface],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = result.communicate()

        if error:
            print(error.decode('utf-8'))
            sys.exit(1)

        output = output.decode('utf-8')

        mac_addr = re.findall(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", output)
        return mac_addr[0]

    def changeMAC(self, mac):
        """
        Changes the MAC address of the selected interface
        """

        colors.info('Changing MAC address...')
        time.sleep(2) # Wait for the interface to be up

        subprocess.call(['ifconfig', self.interface, 'down'])
        subprocess.call(['ifconfig', self.interface,
                         'hw', 'ether', mac])
        subprocess.call(['ifconfig', self.interface, 'up'])

    def resetMAC(self):
        """
        Restores the MAC address of the interface
        """

        self.changeMAC(self.origMAC)

        checkMAC = self.interfaceMAC()

        if checkMAC == self.origMAC:
            colors.success('MAC address restored to default : {}'.format(self.origMAC))
            colors.info('Exiting...')
            sys.exit(1)
        else:
            colors.error('Failed to restore MAC address, trying again...')
            self.resetMAC()

    def startProcess(self):
        """
        Change the MAC address of the interface
        """

        self.changeMAC(self.newMAC)

        checkMAC = self.interfaceMAC()

        if checkMAC == self.newMAC:
            colors.success('MAC address succesfully changed to : {}'.format(self.newMAC))
            choice = str(input('>> Do you want to restore to default (R/r)? ').strip())
            if choice == 'R' or choice == 'r':
                self.resetMAC()
        else:
            colors.error('Failed to change MAC address, trying again...')
            self.startProcess()
