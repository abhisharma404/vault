#! /usr/bin/python

import scanner
from crawler import Crawl
from colorama import *


class XSS(object):

    def __init__(self, url, payload_file):
        self.url = url
        self.payload = payload_file
        self.payload_list = []

    def processPayload(self):
        """This function process payload from file"""

        with open(self.payload) as file:
            for line in file.readlines():
                line = line.strip()
                yield line

    def listPayloads(self):
        for payload in self.processPayload():
            self.payload_list.append(payload)

        return self.payload_list

    def initiateEngine(self):
        print(Fore.GREEEN+'[+] XSS Vulnerability Engine started...'+Fore.RESET)
        self.payload_list = self.listPayloads()
        engine = scanner.Scanner(self.url, self.payload_list)
        engine.inject_payload()
