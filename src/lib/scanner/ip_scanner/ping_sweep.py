#! /usr/bin/python

import time
import subprocess
import sys
import platform
from concurrent.futures import ThreadPoolExecutor
import colors
from vault_cli import errors


class IPScanner(object):

    def __init__(self, ip, start_ip=None, end_ip=None, threads=None):

        if ip is None:
            colors.error('IP address cannot be none.')
            sys.exit(1)
        else:
            self.ip = ip

        if start_ip is None:
            self.start_ip = 0
        else:
            try:
                start_ip = int(start_ip)
            except (ValueError, TypeError):
                errors.report_error('Invalid start IP range', code='E1002',
                                    hint='Provide a numeric start range.')
                sys.exit(1)
            if start_ip < 0 or start_ip > 256:
                errors.report_error('Start range cannot be less than 0 or '
                                    'greater than 256', code='E1002')
                sys.exit(1)
            self.start_ip = start_ip

        if end_ip is None:
            self.end_ip = 256
        else:
            try:
                end_ip = int(end_ip)
            except (ValueError, TypeError):
                errors.report_error('Invalid end IP range', code='E1002',
                                    hint='Provide a numeric end range.')
                sys.exit(1)
            if end_ip > 256 or end_ip < 0:
                errors.report_error('End range cannot be greater than 256 or '
                                    'less than 0', code='E1002')
                sys.exit(1)
            self.end_ip = end_ip

        if threads is None:
            self.threads = 1
        else:
            try:
                self.threads = int(threads)
            except (ValueError, TypeError):
                errors.report_error('Invalid number of threads',
                                    code='E1011',
                                    hint='Provide a numeric thread count.')
                sys.exit(1)

    @staticmethod
    def checkOS():
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
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=False)
            stdout, stderr = process.communicate()
        except Exception as e:
            errors.report_error('Ping sweep failed for {}'
                                .format(ping_ip), exc=e, code='E3001')
            return
        if self.checkStatus(stdout.decode('utf-8')):
            colors.success('Open : {}'.format(ping_ip))
        else:
            colors.error('Closed : {}'.format(ping_ip))

    @staticmethod
    def checkStatus(response):
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
