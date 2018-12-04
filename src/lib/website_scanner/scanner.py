#! /usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import time


class Scanner:

    def __init__(self, url, payload):
        self.target_url = url
        self.payload = payload

    def extract_forms(self, url):
        response = requests.get(url)
        soup_obj = BeautifulSoup(response.text, 'lxml')
        list_forms = soup_obj.findAll('form')
        return list_forms

    def inject_payload(self):

        t1 = time.time()
        for url in self.target_url:
            list_forms = self.extract_forms(url)
            list_of_tasks = []

            for form in list_forms:
                t = threading.Thread(target=self.scanLoad, args=(form, url,))
                t.start()
                list_of_tasks.append(t)

            for task in list_of_tasks:
            	task.join()

        t2 = time.time()

        print('[!] Completed in {}'.format(t2-t1))

    def scanLoad(self, form, url):
        input_box = form.findAll('input')
        post_data = {}

        for i in range(len(self.payload)):
            for box in input_box:
                box_name = box.get('name')
                type_box = box.get('type')
                input_value = box.get('value')
                if type_box == 'text':
                    input_value = self.payload[i]

                post_data[box_name] = input_value

            result = requests.post(url, data=post_data)

            if self.payload[i] in result.text:
                print('\n[!] VULNERABILITY DETECTED!--> ' + self.payload[i])
                print('[*] LINK IS ', url)
                print('---FORM DATA---')
                print(form)
                print('\n')
            else:
                print("[+] OK , Payload : {} , URL : {}".format(self.payload[i], url))
