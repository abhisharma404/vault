#! /usr/bin/python

import threading
from queue import Queue
from . import imutil as imu
from .spider import Spider

class Crawler:

	def __init__(self, url, pname):
		self.pname = pname
		self.url = url
		self.path_crawl = self.pname + "/crawled.txt"
		self.path_queue = pname + "/queue.txt"
		self.queue = Queue()
		self.crawl = set()
		self.domain_name = imu.get_domain_name(self.url)
		print('>>>This may slow down your pc depending upon the website...')
		Spider(self.pname, self.url, self.domain_name, self.path_queue, self.path_crawl)

#    def __init__(self, project_name, base_url, domain_name, path_queue, path_crawl, img_flag):


	def create_spider(self):
		for _ in range(0,1000):
			t = threading.Thread(target = self.work)
			t.daemon = True
			t.start()



	def work(self):
		url = self.queue.get()
		Spider.crawl_page(threading.current_thread().name, url)
		self.queue.task_done()

	def create_jobs(self):
		for link in imu.file_to_set(self.path_queue):
			self.queue.put(link)
		self.queue.join()
		self.start_crawl()


	def start_crawl(self):
		qlinks = imu.file_to_set(self.path_queue)
		if len(qlinks) > 0:
			print(str(len(qlinks)) + ' Left to be Crawled.')
			self.create_jobs()

	def start(self, return_set:bool):
		self.create_spider()
		self.start_crawl()
		if return_set == True:
			return imu.file_to_set(self.path_crawl),self.pname
		else:
			return ''