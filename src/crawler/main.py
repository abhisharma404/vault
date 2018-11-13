#!/usr/bin/env python
# Python Web Crawler

"""Implementing a very basic Python Web Crawler that uses Breadth First Search (BFS) and recursion to list all the URLs"""

from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse


links_visited = []
to_visit = ['http://www.cuchd.in']

def checkValidity(link):
    url = urlparse(link)
    url = url.netloc
    try:
        url = url.split('.')
    except:
        pass
    try:
        if url[1] == 'cuchd':
            return True
    except:
        pass

def getLinks(list_obj):
    link = list_obj.pop(0)
    r = requests.get(link)
    if r:
        links_visited.append(link)
    else:
        to_visit.append(link)
    soup_obj = BeautifulSoup(r.text, 'lxml')
    links = soup_obj.findAll('a')
    for link in links:
        url = link.get('href')
        if checkValidity(url):
            print('[+] Found -> ', url)
            if url not in to_visit and url not in links_visited:
                to_visit.append(url)
    getLinks(list_obj)

getLinks(to_visit)
