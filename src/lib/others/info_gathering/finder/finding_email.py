#! /usr/bin/python

import requests
import re
import colors


class FindingEmails(object):

    def __init__(self, url):
        self.url = url
        self.found_emails = []

    def get_source_code(self):
        resp_text = requests.get(self.url).text
        return resp_text

    def find_email(self):
        source_code = self.get_source_code()
        self.found_emails = re.findall(r'[\w\.-]+@[\w\.-]+', source_code)

    def parse_emails(self):
        self.find_email()
        if len(self.found_emails) > 0:
            for email in self.found_emails:
                colors.success('Found {}'.format(email))
        else:
            colors.error('No email found')
            print('No email found')

        return self.found_emails
