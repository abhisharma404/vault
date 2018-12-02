#!/usr/bin/env python
# Python Web Crawler

"""Implementing a Python Web Crawler that uses Breadth First Search (BFS) and recursion to list all the URLs"""

from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse, urljoin


links_visited = []
to_visit = []
url_netloc = None
base_url = None


def start_crawling(url):
    global to_visit
    global url_netloc

    url_netloc = urlparse(url).netloc

    to_visit.append(url)
    getLinks()


def checkValidity(link):
    global url_netloc
    path = ''
    query = ''

    url = urlparse(link)

    netloc = url.netloc

    if netloc == '':
        path = url.path
        query = url.query
    try:
        netloc = netloc.split('.')
    except:
        pass
    try:
        print(netloc[1])
        if netloc[1] == url_netloc or path != '' or query != '':
            return True
    except:
        pass


def getLinks():
    global base_url
    global to_visit
    global links_visited

    link = to_visit.pop(0)
    print(link)
    r = requests.get(link)
    if r:
        links_visited.append(link)
    else:
        to_visit.append(link)
    if r:
        soup_obj = BeautifulSoup(r.text, 'lxml')
        links = soup_obj.findAll('a')
        for link in links:
            url = link.get('href')
            if checkValidity(url):
                print('[+] Found -> ', url)
                if url not in to_visit and url not in links_visited:
                    url = urljoin(base_url, url)
                    print(url)
                    to_visit.append(url)
    getLinks()


if __name__ == '__main__':

    url = str(input('Enter the URL to crawl...'))
    if not url.startswith('http'):
        url = 'http://' + url
        print(url)
    start_crawling(url)
