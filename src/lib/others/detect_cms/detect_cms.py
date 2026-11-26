#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import *
from collections import defaultdict
import sys
import os
import json
import colors
import operator
from vault_cli import lib, errors


class DetectCMS(object):

    def __init__(self, url):
        self.url = url
        self.scores = defaultdict(int)
        self.success_codes = [200, 201, 202, 203, 204, 205, 206]
        self.redirection_codes = [300, 301, 302, 303, 304, 305, 306, 307]
        self.payloads = []

    def read_payloads(self):
        try:
            payloads_path = lib.payload_path('detect_cms')
            if not os.path.exists(payloads_path):
                raise Exception("Payloads folder does not exists")
        except Exception as e:
            errors.report_error(str(e), exc=e, code='E6002')
            sys.exit(1)

        for file in os.listdir(payloads_path):
            if file.endswith(".json"):
                file = os.path.join(payloads_path, file)
                with open(file) as payload_file:
                    self.payloads.append(json.load(payload_file))

    def _safe_get(self, url):
        """GET ``url``, reporting E2001 and returning None on failure."""
        try:
            return requests.get(url)
        except requests.exceptions.RequestException as e:
            errors.report_error('CMS detection request failed: {}'
                                .format(url), exc=e, code='E2001')
            return None

    def detect_cms(self):
        for cms in self.payloads:
            response = None
            for payload in cms["code"]:
                if payload["type"] == "tag-contains":
                    for line in self.soup_obj.find_all(payload["value"]
                                                       ["element"]):
                        if str(line.get("name")).lower()\
                           == payload["value"]["name"]:
                            if payload["value"]["text"] in \
                               str(line.get("content")).lower():
                                self.scores[cms["CMS"]["name"]] += 1
                if payload["type"] == "regex":
                    if re.search(payload["value"], self.response.text):
                        self.scores[cms["CMS"]["name"]] += 1
            for payload in cms["file"]:
                if payload["type"] == "request":
                    response = self._safe_get(urljoin(self.url,
                                                      payload["value"]["url"]))
                    if response is not None and (response.status_code in
                                                 self.success_codes or
                                                 response.status_code in
                                                 self.redirection_codes or
                                                 response.status_code == 403):
                        self.scores[cms["CMS"]["name"]] += 1
                if payload["type"] == "request-header":
                    for header in self.response.headers:
                        if payload["value"]["text"] in\
                           str(header + ": " +
                               self.response.headers[header]).lower():
                            self.scores[cms["CMS"]["name"]] += 1
                if payload["type"] == "request-contains":
                    response = self._safe_get(urljoin(self.url,
                                                      payload["value"]["url"]))
                    if response is not None and (response.status_code in
                                                 self.success_codes or
                                                 response.status_code in
                                                 self.redirection_codes or
                                                 response.status_code == 403):
                        if payload["value"]["text"] in response.text.lower():
                            self.scores[cms["CMS"]["name"]] += 1
                if payload["type"] == "request-regex":
                    response = self._safe_get(urljoin(self.url,
                                                      payload["value"]["url"]))
                    if response is not None and (response.status_code in
                                                 self.success_codes or
                                                 response.status_code in
                                                 self.redirection_codes or
                                                 response.status_code == 403):
                        if re.search(payload["value"]["regex"],
                                     response.text.lower()):
                            self.scores[cms["CMS"]["name"]] += 1
                if payload["type"] == "match-request-contains":
                    if response is None:
                        continue
                    match = re.search(payload["value"]["regex"],
                                      response.text.lower())
                    if match:
                        response = self._safe_get(
                            urljoin(self.url, match.group(0) +
                                    payload["value"]["url"]))
                        if response is not None and (response.status_code in
                                                     self.success_codes or
                                                     response.status_code in
                                                     self.redirection_codes or
                                                     response.status_code ==
                                                     403):
                            if payload["value"]["text"]\
                               in response.text.lower():
                                self.scores[cms["CMS"]["name"]] += 1

    def start_engine(self):
        try:
            self.response = requests.get(self.url)
        except requests.exceptions.RequestException as e:
            errors.report_error('CMS detection failed to reach {}'
                                .format(self.url), exc=e, code='E2001')
            return
        self.soup_obj = BeautifulSoup(self.response.text, "html.parser")

        colors.info("Starting CMS Detect engine...")
        colors.info("Reading payloads...")
        self.read_payloads()
        colors.info("Detecting CMS...")
        self.detect_cms()

        if not self.scores:
            colors.warning('No CMS signatures matched; framework could not '
                           'be determined.')
            return

        colors.success("Detected framework: {}"
                       .format(max(self.scores.items(),
                                   key=operator.itemgetter(1))[0]))
