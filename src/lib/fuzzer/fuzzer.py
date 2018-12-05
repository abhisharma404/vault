#! /usr/bin/python

import requests
from urllib.parse import urljoin
import time
import threading
import multiprocessing
import os
import sys
from colorama import * 


class Fuzzer(object):

    """fuzzObj = Fuzzer(base_url='http://sample-site', thread_num=10, fuzz_file_path='fuzz_url.txt')"""

    def __init__(self, base_url=None, thread_num=None):
        self.m = multiprocessing.Manager()
        self.base_url = base_url
        try:
            self.fuzz_file_path = os.getcwd() + '/payloads/fuzz_url.txt'
            if not os.path.exists(self.fuzz_file_path):
                raise Exception('Directory does not exist')
        except Exception as e:
            print(Fore.BLUE+'[-]'+Fore.RESET, e)
            sys.exit(1)
        if thread_num is None:
            self.thread_num = 1
        else:
            self.thread_num = int(thread_num)
        self.fuzz_queue = self.m.Queue()
        self.discovered_url = []
        self.redirected_url = []
        self.success_codes = [200, 201, 202, 203, 204, 205, 206]
        self.redirection_codes = [300, 301, 302, 303, 304, 305, 306, 307]

    def readFromFile(self):
        with open(self.fuzz_file_path) as file:
            for fuzz_text in file.readlines():
                self.fuzz_queue.put(fuzz_text)

    def send_request(self, url):
        resp = requests.get(url)
        if resp.status_code in self.success_codes:
            return 1
        elif resp.status_code in self.redirection_codes:
            print(resp.status_code)
            return 2
        else:
            return 0

    def generate_url(self, fuzz_text):
        return urljoin(self.base_url, fuzz_text)

    def start_engine(self):
        while not self.fuzz_queue.empty():
            fuzz_text = self.fuzz_queue.get()
            fuzz_url = self.generate_url(fuzz_text)
            self.fuzz_queue.task_done()

            try:
                status = self.send_request(fuzz_url)
                if status == 1:
                    print(Fore.BLUE+'[+] Found -> '+Fore.RESET, fuzz_url)
                    self.discovered_url.append(fuzz_url)
                elif status == 2:
                    print(Fore.BLUE+'[!] Redirection Detected -> '+Fore.RESET, fuzz_url)
                    self.redirected_url.append(fuzz_url)
            except Exception as e:
                print(e)

    def initiate(self):
        self.readFromFile()
        t1 = time.time()

        threads = []

        print(Fore.GREEN+'[!] URL Fuzzing started...'+Fore.RESET)

        for _ in range(self.thread_num):
            newThread = threading.Thread(target=self.start_engine)
            newThread.start()
            threads.append(newThread)

        for thread in threads:
            thread.join()

        t2 = time.time()

        print(Fore.GREEN+'[!] Successfully completed in : {} seconds.'+Fore.RESET .format(t2-t1))
