#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
import colors


class FindingComments(object):

    def __init__(self, url):
        self.url = url
        self.comment_list = ['<!--(.*)-->']
        self.found_comments = {}

    def get_soure_code(self):
        resp_text = requests.get(self.url).text
        return resp_text

    def find_comment(self):
        source_code = self.get_soure_code()
        for comment in self.comment_list:
            comments = re.findall(comment, source_code)
            self.found_comments[comment] = comments

    def parse_comments(self):
        self.find_comment()
        comment_dict = {}
        if len(self.found_comments) > 0:
            for comment_code, comment in self.found_comments.items():
                colors.success('Found for {} : {}'.format(comment_code, comment))
                comment_dict[comment_code] = comment
        else:
            colors.error('No comment found')

        return comment_dict
