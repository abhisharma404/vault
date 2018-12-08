#! /usr/bin/python

import time
import subprocess
import sys
import platform
from concurrent.futures import ThreadPoolExecutor
import colors


class IPScanner(object):

    def __init__(self, ip, start_ip=None, end_ip=None, threads=None):

        if ip is None:
            colors.error('IP address cannot be none.')
            sys.exit(1)
        else:
            self.ip = ip

        if start_ip is None:
            self.start_ip = 0
        elif (int(start_ip) < 0 or int(start_ip) > 256):
            colors.error('Start range cannot be less than 0 or greater than 256')
            sys.exit(1)
        else:
            self.start_ip = int(start_ip)

        if end_ip is None:
            self.end_ip = 256
        elif (int(end_ip) > 256 or int(end_ip) < 0):
            colors.error('End range cannot be greater than 256 or less than 0')
            sys.exit(1)
        else:
            self.end_ip = int(end_ip)

        if threads is None:
            self.threads = 1
        else:
            self.threads = int(threads)

    def checkOS(self):
        oper = platform.system()
        if (oper == 'Windows'):
            return ['ping', '-n', '1']
        else:
            return ['ping', '-c', '1']

    def setIP(self):
        self.ip = self.ip.split('.')[0:3]
        self.ip = '.'.join(self.ip)

    def pingScan(self, end):
        ping_ip = self.ip + '.' + str(end)
        command = self.checkOS()
        command.append(ping_ip)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout, stderr = process.communicate()
        if self.checkStatus(stdout.decode('utf-8')):
            colors.success('Open : {}'.format(ping_ip))
        else:
            colors.error('Closed : {}'.format(ping_ip))

    def checkStatus(self, response):
        if 'ttl' in response:
            return True

    def threadingScan(self):

        t1 = time.time()

        self.setIP()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            tasks = []
            for ip in range(self.start_ip, self.end_ip):
                task = executor.submit(self.pingScan, (ip))
                tasks.append(task)

        t2 = time.time()

        colors.info('Completed in {}'.format(t2-t1))
