""" This module is meant for the type of injections that can be done"""
import scanner


class Injection(object):

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
        #print("Initiating Engine...")
        self.payload_list = self.listPayloads()
        # print(self.payload_list)
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
