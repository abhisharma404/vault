import type
from crawler import Crawl

target_url = 'http://10.0.2.6/mutillidae/'
payload_file = 'xss_payloads.txt'

crawler = Crawl(target_url)
list_of_urls = crawler.getList()

for url in list_of_urls:
    xss_obj = type.XSS(url,payload_file)
    xss_obj.initiateEngine()
