#!/usr/bin/env python

import random
import requests
import colors


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
            print(e)
            return False

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

            # Now Sart Scanning
            for _url in urls:
                for _payload in _payloads:
                    scan_url = _url+_payload
                    res = requests.get(scan_url, headers=self.scan_headers)

                    for _match in _matches[_payload]:
                        if _match in res.text:
                            colors.success("LFI Detected!: {}"
                                           .format(scan_url))
                            success_count += 1
                        if "syntax error" in res.text:
                            colors.error("Syntax Parse Error: {}"
                                         .format(scan_url))

            # Still no success, now check with null byte
            if success_count == 0:
                colors.info("Now creating payloads with one NULL BYTE suffix.")
                for _url in urls:
                    for _payload in _payloads:
                        scan_url = _url+_payload+null_byte
                        res = requests.get(scan_url, headers=self.scan_headers)

                        for _match in _matches[_payload]:
                            if _match in res.text:
                                colors.success("LFI Detected! : {}"
                                               .format(scan_url))
                                success_count += 1
                            if "syntax error" in res.text:
                                colors.error("Syntax Parse Error:{}"
                                             .format(scan_url))

            if success_count == 0:
                colors.error('No LFI Detected')

        else:
            colors.error('An error occured, make sure provided URL is valid '
                         'and accessible.')
