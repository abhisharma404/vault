#! /usr/bin/python

from . import scanner
import colors
from .crawler import Crawl
from vault_cli import errors


class XSS(object):

    def __init__(self, url, payload_file):
        self.url = url
        self.payload = payload_file
        self.payload_list = []

    def processPayload(self):
        """This function process payload from file"""

        try:
            with open(self.payload) as file:
                for line in file.readlines():
                    line = line.strip()
                    yield line
        except OSError as e:
            errors.report_error('Could not read XSS payload file: ' +
                                str(self.payload), exc=e, code='E6002')

    def listPayloads(self):
        for payload in self.processPayload():
            self.payload_list.append(payload)

        return self.payload_list

    def initiateEngine(self):
        colors.info('XSS Vulnerability Engine started...')
        self.payload_list = self.listPayloads()
        engine = scanner.Scanner(self.url, self.payload_list)
        engine.inject_payload()
