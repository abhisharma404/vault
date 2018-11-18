import requests
from urllib.parse import urljoin
import queue
import time
import threading

discovered_url = []

def generate_url(base_url, fuzz_text):
    return urljoin(base_url, fuzz_text)


def readFromFile(file_path):
    fuzz_queue = queue.Queue()
    with open(file_path) as file:
        for url in file.readlines():
            fuzz_queue.put(url)
    return fuzz_queue


def send_request(url):
    resp = requests.get(url)
    if resp.status_code == 200:
        return True


def startEngine():
    queue_generated = readFromFile('fuzz_url.txt')
    while not queue_generated.empty():
        new_url = generate_url('http://10.0.2.6/mutillidae', queue_generated.get())
        try:
            if send_request(new_url):
                print('[+] ', new_url)
                discovered_url.append(url)
                #print(threading.current_thread())
        except:
            pass



if __name__ == '__main__':

    t1 = time.time()

    # threads = []
    #
    # for i in range(10):
    #     thread = threading.Thread(target=startEngine)
    #     thread.start()
    #     threads.append(thread)
    #
    # for thread in threads:
    #     thread.join()

    startEngine()

    t2 = time.time()

    print('Completed in {}'.format(t2-t1))
