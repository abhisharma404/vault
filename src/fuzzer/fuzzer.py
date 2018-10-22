import requests
from urllib.parse import urljoin
import queue
import time
import threading


def generate_url(base_url, fuzz_text):
    new_url = base_url + '/' + fuzz_text
    return new_url

def readFromFile(file_path):
    myQueue = queue.Queue()
    with open(file_path) as file:
        for url in file.readlines():
            myQueue.put(url)
    return myQueue

def send_request(url):
    resp = requests.get(url)
    if resp.status_code == 200:
        return True

def startEngine():
    while not queue_generated.empty():
        new_url = generate_url('http://10.0.2.6/mutillidae', queue_generated.get())
        try:
            if send_request(new_url):
                print('[+] ', new_url)
                print(threading.current_thread())
        except:
            pass


if __name__ == '__main__':
    queue_generated = readFromFile('fuzz_url.txt')

    t1 = time.time()

    threads = []

    for i in range(10):
        thread = threading.Thread(target=startEngine)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    t2 = time.time()

    print('Completed in {}'.format(t2-t1))
