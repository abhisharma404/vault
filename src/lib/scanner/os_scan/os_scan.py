#! /usr/bin/python
import sys
import os
import nmap
import colors
from urllib.parse import urlparse


class OSScan(object):

    def __init__(self, url, ip):
        self.is_root()

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScanner:
            colors.error('Nmap not found')
            sys.exit(1)
        except Exception as e:
            print(e)
            sys.exit(1)

        if url is not None and ip is not None:
            colors.error('Please provide either the URL or the IP address...')
            sys.exit(1)

        if ip is not None:
            self.target = ip
        elif url is not None:
            self.target = self.check_url(url)
        else:
            colors.error('Please provide URL or the IP address to scan...')

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
    def check_url(url):
        """
        Delete the scheme of the URL
        """
        url = urlparse(url).netloc

        return url

    def os_scan(self):
        colors.info('OS Scan running on: {}'.format(self.target))

        self.nm.scan(self.target, arguments="-O")
        if len(self.nm[self.nm.all_hosts()[0]]["osmatch"]) != 0:
            colors.success('OS Scan results of: {}'.
                           format(self.nm.all_hosts()[0]))
            for osmatch in self.nm[self.nm.all_hosts()[0]]["osmatch"]:
                print("[+] Name: {}".format(osmatch["name"]))
                print("[+] Accuracy: {}".format(osmatch["accuracy"]))
        else:
            colors.info('No OS matches for host')
