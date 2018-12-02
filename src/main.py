import type
from crawler import Crawl
import threading
import time

target_url = 'http://10.0.2.6/mutillidae/'
payload_file = 'xss_payloads.txt'

crawler = Crawl(target_url)
list_of_urls = crawler.getList()

task_list = []


def startThread(url):
    xss_obj = type.XSS(url, payload_file)
    xss_obj.initiateEngine()


t1 = time.time()

for url in list_of_urls:
    # t = threading.Thread(target=startThread, args=(url,))
    # t.start()
    # task_list.append(t)
    startThread(url)

# for t in task_list:
#     t.join()

t2 = time.time()
print('The time taken is {}'.format(t2-t1))
