import requests
from urllib.parse import urljoin
import time
import threading
import multiprocessing

import os
import sys

from colorama import init
from termcolor import colored

def successMessage(message):
    init()
    print(colored(message, 'green'))

class Fuzzer(object):

    def __init__(self, fuzz_file_path, base_url, thread_num):
        self.m = multiprocessing.Manager()
        self.base_url = base_url
        self.fuzz_file_path = fuzz_file_path
        self.thread_num = thread_num
        self.fuzz_queue = self.m.Queue()
        self.discovered_url = []
        self.sucess_codes = ['200', '201', '202', '203', '204', '205', '206']
        self.redirection_codes = ['300', '301', '302', '303', '304', '305', '306', '307']

    def readFromFile(self):
        with open(self.fuzz_file_path) as file:
            for fuzz_text in file.readlines():
                self.fuzz_queue.put(fuzz_text)

    def send_request(self, url):
        resp = requests.get(url)
        if resp.status_code in self.sucess_codes:
            return 1
        elif resp.status_code in self.redirection_codes:
            return 2
        else:
            return 0

    def generate_url(self, fuzz_text):
        return urljoin(self.base_url, fuzz_text)

    def start_engine(self):
        self.readFromFile()
        while not self.fuzz_queue.empty():
            fuzz_text = self.fuzz_queue.get()
            fuzz_url = self.generate_url(fuzz_text)
            self.fuzz_queue.task_done()
            try:
                status = self.send_request(fuzz_url)
                if status == 1:
                    print('[+]', fuzz_url)
                    self.discovered_url.append(fuzz_url)
                elif status == 2:
                    print('[!] Redirection detected...')
            except Exception as e:
                print(e)

    def initiate(self):
        t1 = time.time()

        threads = []

        successMessage('[!] URL Fuzzing started...')

        for _ in range(self.thread_num):
            newThread = threading.Thread(target=self.start_engine)
            newThread.start()
            threads.append(newThread)

        for thread in threads:
            thread.join()

        t2 = time.time()

        print('[!] Successfully completed in : {} seconds.'.format(t2-t1))


if __name__ == '__main__':

    fuzzObj = Fuzzer(base_url='http://10.0.2.6/mutillidae', thread_num=10, fuzz_file_path='fuzz_url.txt')
    fuzzObj.initiate()
