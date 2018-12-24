from urllib.parse import unquote
import colors
import requests
from bs4 import BeautifulSoup
import logger
import logging
import os


log_file_name = os.path.join(os.getcwd(), "vault.log")
logger.Logger.create_logger(log_file_name, __package__)
LOGGER = logging.getLogger(__name__)


def modifyLINK(url):
    list1 = []
    for ch in url:
        if ch == "&":
            break
        else:
            list1.append(ch)
    ret = ''.join(list1)
    return ret


def start_dorking(search, page_count):
    web_list = []
    m_search = modifyLINK(search)
    count = 0
    page_count *= 10
    while page_count != count:
        count = str(count)
        m_search = str(m_search)
        search_url = "https://google.com/search?q=" + m_search + "&start=" +\
                     count
        requested_page = requests.get(search_url).text
        soup = BeautifulSoup(requested_page, 'html.parser')
        count = int(count)
        if "Our systems have detected unusual traffic from your computer"\
           "network" in soup.get_text():
            colors.error("Google has detected the script. Try after some "
                         "time.")
            LOGGER.error('[-] script blocked by google. wait for some minutes')
            break
        h3_tags = soup.findAll("h3")
        for h3 in h3_tags:
            a_tag = h3.find("a")
            link = a_tag.get("href")
            link = link[7:]
            if link.startswith("http"):
                searchlink = modifyLINK(link)
                res = unquote(searchlink)
                web_list.append(res)
                print("\033[1;37m--> \033[1;32m", res, end=" \n")
        count += 10

    return web_list
