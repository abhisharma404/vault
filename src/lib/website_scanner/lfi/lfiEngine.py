#!/usr/bin/env python

from . import lfiScanner
import json
from vault_cli import errors


class LFI(object):

    def __init__(self, url, payload_path):
        self.url = url
        try:
            with open(payload_path, 'r') as f:
                self.payload_data = json.load(f)
        except OSError as e:
            errors.report_error('Could not read LFI payload file: ' +
                                str(payload_path), exc=e, code='E6002')
            self.payload_data = {}
        except ValueError as e:
            errors.report_error('LFI payload file is not valid JSON: ' +
                                str(payload_path), exc=e, code='E6002')
            self.payload_data = {}

    def startScanner(self):
        engine = lfiScanner.Scanner(url=self.url,
                                    payload_data=self.payload_data)
        engine.scan()
