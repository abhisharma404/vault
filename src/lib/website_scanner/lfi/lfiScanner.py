#!/usr/bin/env python

import random
import requests
import colors
from vault_cli import errors


class Scanner(object):

    def __init__(self, url, payload_data):
        self.url = url
        self.payload_data = payload_data
        self.scan_headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; '
                                           'Intel Mac OS X 10_10; rv:33.0) '
                                           'Gecko/20100101 Firefox/33.0', }

    def check_url(self, url):
        ua_list = [
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 \
                Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 \
                Firefox/36.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) \
                Gecko/20100101 Firefox/33.0',
            'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 \
                Firefox/31.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) \
                AppleWebKit/537.13+ (KHTML, like Gecko) Version/5.1.7 \
                Safari/534.57.2',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) \
                AppleWebKit/534.55.3 (KHTML, like Gecko) \
                Version/5.1.3 Safari/534.53.10'
        ]
        ua = random.choice(ua_list)
        headers = {
            'User-Agent': ua,
        }

        colors.info('Checking the URL if it is live')
        try:
            response = requests.get(url, headers=headers)
            response_code = response.status_code
            colors.info('Got a respose for the URL with status code:{}'
                        .format(response_code))

            if response_code == 200:
                self.scan_headers = headers
                return True
            else:
                return False
        except Exception as e:
            errors.report_error(str(e), exc=e, code='E2001')
            return False

    def get(self, scan_url):
        """Perform a request, returning the response body text or None.

        Connection errors (e.g. a server dropping a request with a NULL-byte
        suffix) are skipped rather than aborting the whole scan.
        """
        try:
            res = requests.get(scan_url, headers=self.scan_headers, timeout=10)
            return res.text
        except requests.exceptions.RequestException:
            return None

    def scan(self):
        null_byte = "%00"
        success_count = 0
        url = self.url
        ck = self.check_url(url)
        if ck:
            _matches = self.payload_data["linux"]
            _payloads = self.payload_data["linux"].keys()
            _prefixs = self.payload_data["linuxPrefix"]

            urls = []
            for _prefix in _prefixs:
                urls.append(url+_prefix)

            # Now Start Scanning
            for _url in urls:
                for _payload in _payloads:
                    scan_url = _url+_payload
                    res = self.get(scan_url)
                    if res is None:
                        continue

                    for _match in _matches[_payload]:
                        if _match in res:
                            colors.success("LFI Detected!: {}"
                                           .format(scan_url))
                            success_count += 1
                        if "syntax error" in res:
                            colors.error("Syntax Parse Error: {}"
                                         .format(scan_url))

            # Still no success, now check with null byte
            if success_count == 0:
                colors.info("Now creating payloads with one NULL BYTE suffix.")
                for _url in urls:
                    for _payload in _payloads:
                        scan_url = _url+_payload+null_byte
                        res = self.get(scan_url)
                        if res is None:
                            continue

                        for _match in _matches[_payload]:
                            if _match in res:
                                colors.success("LFI Detected! : {}"
                                               .format(scan_url))
                                success_count += 1
                            if "syntax error" in res:
                                colors.error("Syntax Parse Error:{}"
                                             .format(scan_url))

            if success_count == 0:
                colors.error('No LFI Detected')

        else:
            errors.report_error('An error occured, make sure provided URL is '
                                'valid and accessible.', code='E3001')
