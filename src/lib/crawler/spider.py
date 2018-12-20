#! /usr/bin/python


import urllib.request
import urllib.response
from . import finder as fobj
from . import imutil as imu


class Spider:

    project_name = ''
    base_url = ''
    domain_name = ''
    queue_file = ''
    crawled_file = ''
    queue = set()
    crawled = set()

    def __init__(self, project_name, base_url, domain_name, path_queue, path_crawl):
        Spider.project_name = project_name
        Spider.base_url = base_url
        Spider.domain_name = domain_name
        Spider.queue_file = path_queue
        Spider.crawled_file = path_crawl
        self.boot()
        self.crawl_page('First spider', Spider.base_url)


    @staticmethod
    def boot():
        imu.create_project_dir(Spider.project_name)
        imu.create_data_files(Spider.project_name, Spider.base_url)#Entering first url
        #print('Writing First Url' + Spider.base_url)
        Spider.queue = imu.file_to_set(Spider.queue_file)
        #print(str(len(Spider.queue)))
        Spider.crawled = imu.file_to_set(Spider.crawled_file)


    @staticmethod
    def crawl_page(thread_name, page_url):
        ############ TO CHECK IF LINK has been crawled  #######
        if page_url not in Spider.crawled:
            print(thread_name + ' now crawling ' + page_url)
            print('Queue ' + str(len(Spider.queue)) + ' | Crawled  ' + str(len(Spider.crawled)))
            Spider.add_links_to_queue(Spider.gather_links(page_url))
            Spider.queue.remove(page_url)#<<<<<<<<<<<<<<<<___<<<<<<<
            Spider.crawled.add(page_url)
            Spider.update_files()


    @staticmethod
    def gather_links(page_url):
        html_string = ''
        try:
            req = urllib.request.Request(page_url, headers ={'User-Agent':'Mozilla/5.0'})
            con = urllib.request.urlopen(req)
            html_string=con.read().decode("utf-8")
            obj = fobj.Linkfinder(Spider.base_url)
            obj.feed(html_string)
            return obj.links_obtained()

        except Exception as e:
            print("Exception Occured!!!\n"+ str(e))
            return ''
        pass


    @staticmethod
    def add_links_to_queue(links):
        for url in links:
            if (url in Spider.queue) or (url in Spider.crawled):
                continue
            if Spider.domain_name != imu.get_domain_name(url):
                continue
            print(url)
            Spider.queue.add(url)


    @staticmethod
    def update_files():
        imu.set_to_file(Spider.queue, Spider.queue_file)
        imu.set_to_file(Spider.crawled, Spider.crawled_file)
