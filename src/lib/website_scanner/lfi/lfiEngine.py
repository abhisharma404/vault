#!/usr/bin/env python

from . import lfiScanner
import json

class LFI(object):

    def __init__(self,url,payload_path):
        self.url=url
        with open(payload_path, 'r') as f:
            self.payload_data = json.load(f)

    def startScanner(self):
        engine = lfiScanner.Scanner(url=self.url, payload_data=self.payload_data)
        engine.scan()