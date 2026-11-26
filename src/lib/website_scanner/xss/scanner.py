#! /usr/bin/python

import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import colors
import time
from vault_cli import errors


class Scanner:

    def __init__(self, url, payload):
        self.target_url = url
        self.payload = payload

    def extract_forms(self, url):
        try:
            response = requests.get(url, timeout=15)
        except requests.exceptions.RequestException as e:
            errors.report_error('Request failed while fetching forms from: ' +
                                url, exc=e, code='E2001')
            return []
        soup_obj = BeautifulSoup(response.text, 'html.parser')
        list_forms = soup_obj.findAll('form')
        return list_forms

    def inject_payload(self):

        t1 = time.time()
        if not self.payload:
            colors.warning('Payload list is empty; nothing to inject.')
            return
        if len(self.target_url) > 1:
            for url in self.target_url:
                list_forms = self.extract_forms(url)
                if len(list_forms) == 0:
                    colors.error('No form found for : {}'.format(url))
                list_of_tasks = []

                for form in list_forms:
                    t = threading.Thread(target=self.scanLoad,
                                         args=(form, url,))
                    t.start()
                    list_of_tasks.append(t)

                for task in list_of_tasks:
                    task.join()
        else:
            url = self.target_url[0]
            list_forms = self.extract_forms(url)
            if len(list_forms) == 0:
                colors.error('No form found for : {}'.format(url))
            list_of_tasks = []

            for form in list_forms:
                t = threading.Thread(target=self.scanLoad, args=(form, url,))
                t.start()
                list_of_tasks.append(t)

            for task in list_of_tasks:
                task.join()

        t2 = time.time()

        colors.info('Completed in {}'.format(t2-t1))

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

            try:
                result = requests.post(url, data=post_data, timeout=15)
            except requests.exceptions.RequestException:
                # Per-payload failures are expected during injection tests;
                # keep them console-only so they do not flood the error log.
                colors.warning('Request failed while injecting payload into: '
                               + url)
                continue

            if self.payload[i] in result.text:
                colors.info('VULNERABILITY DETECTED!--> {}'
                            .format(self.payload[i]))
                colors.success('Link is : {} '.format(url))
                colors.info('Form Data')
                print(form)
                print('\n')
            else:
                colors.success("OK , Payload : {} , URL : {}"
                               .format(self.payload[i], url))
