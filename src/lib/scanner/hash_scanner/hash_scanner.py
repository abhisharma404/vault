#! /usr/bin/python

import hashlib
import os
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import sys
import time
import colors


class HashScanner(object):

    def __init__(self,
                 list_scans=None,
                 file_path=None,
                 threads=None):

        if file_path is not None:
            self.file_path = file_path
        else:
            colors.error('File path cannot be empty, please specify the path '
                         'to scan')
            sys.exit(1)

        if list_scans is not None:
            self.list_scans = list_scans
        else:
            colors.error('No scanning mode provided, exiting...')
            sys.exit(1)

        if threads is not None:
            threads = int(threads)
            self.threadValidator(threads)
        else:
            self.threads = 10
            colors.info('No threads set, hence using {} threads.'
                        .format(self.threads))

        self.file_list = []
        m = multiprocessing.Manager()
        self.sharedDict = m.dict()

        deepScan_choice = str(input('>> Do you want to perform a deep scan'
                                    ' i.e. scan all sub-directories? (Y/N): '))
        if deepScan_choice == 'Y' or deepScan_choice == 'y':
            self.deepScan = True
        else:
            self.deepScan = False

        self.scanDirectory()

    @staticmethod
    def extractBytes(file_path):
        """
        Extracts and returns bytes of the file
        """

        with open(file_path) as file:
            file_bytes = file.read()
            file_bytes = file_bytes.encode()

        return file_bytes

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

    def scanDirectory(self):
        """
        Scans the directory and
        collects all the file paths
        """

        file_path = self.file_path
        if file_path:
            for root, dirs, files in os.walk(file_path):
                if files:
                    for file in files:
                        temp_path = os.path.join(root, file)
                        self.file_list.append(temp_path)

                    if self.deepScan is False:
                        break

    def scanFile(self, file_path, mode):
        """
        Scans the file path for
        the selected mode
        """

        file_bytes = self.extractBytes(file_path)
        temp_name = str(file_path) + ' -> ' + str(mode)
        temp_dict = {temp_name: eval('hashlib.{}(file_bytes)'
                                     .format(mode)).hexdigest()}
        self.sharedDict.update(temp_dict)

    def modeScan(self, mode):
        """
        Divides the scanning into multiple threads
        making the scan fast
        """

        mode_list = []
        mode_list.append(mode)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scanFile,
                         self.file_list,
                         mode_list * len(self.file_list))

    def startScan(self):
        """
        Distributes the list of scans into
        multiple processor and starts the scan
        """

        colors.info('Hash scanning started...')
        colors.info('Press CTRL+C to stop...')

        t1 = time.time()

        try:
            processes = []

            for mode in self.list_scans:
                newProcess = multiprocessing.Process(target=self.modeScan,
                                                     args=(mode,))
                newProcess.start()
                processes.append(newProcess)

            for process in processes:
                process.join()

        except KeyboardInterrupt:
            colors.error('Stopping the process...')

        except Exception as e:
            print(e)

        finally:
            t2 = time.time()
            colors.success('Completed in {}'.format(t2-t1))
            resultDict = self.parseResult()
            return resultDict

    def parseResult(self):
        """
        Prints the scan result
        """
        print('\n', '=' * 25, 'HASH SCAN RESULT', '=' * 25, '\n')

        for key, item in self.sharedDict.items():
            print('[+] {} : {}'.format(key, item))

        return self.sharedDict
