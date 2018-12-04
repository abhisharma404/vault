#! /usr/bin/python

import scanner


class Injection(object):

    def __init__(self, url, payload_file):
        self.url = []
        self.url.append(url)
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
        print('[+] Vulnerability Engine started...')
        self.payload_list = self.listPayloads()
        engine = scanner.Scanner(self.url, self.payload_list)
        engine.inject_payload()


class XSS(Injection):

    pass


class SQLi(Injection):

    pass


class RFI(Injection):

    pass


class LFI(Injection):

    pass


if __name__ == '__main__':

    newObj = Injection(url='http://10.0.2.6/mutillidae/index.php?page=text-file-viewer.php', payload_file='xss_payloads.txt')
    newObj.initiateEngine()
