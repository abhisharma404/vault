#! /usr/bin/python

import requests
import shutil
import os
import urllib


def image_download(url, name):
    r = requests.get(url, stream=True, headers={'User-agent': 'Mozilla/5.0'})
    if r.status_code == 200:
        with open(name + '.png', 'wb') as f:
            r.raw.decode_content = True
            shutil.copyfileobj(r.raw, f)
            print(url + ' [Downloaded]')
    else:
        print('Download for ' + name + ' Failed.')


def create_project_dir(directory):
    if not os.path.exists(directory):
        print('Creating directory ' + directory)
        os.makedirs(directory)


def create_data_files(project_name, base_url):
    queue = os.path.join(project_name, 'queue.txt')
    crawled = os.path.join(project_name, "crawled.txt")
    if not os.path.isfile(queue):
        write_file(queue, base_url)
    if not os.path.isfile(crawled):
        write_file(crawled, '')


def write_file(path, data):
    with open(path, 'w') as f:
        f.write(data)


def file_to_set(file_name):
    results = set()
    with open(file_name, 'rt') as f:
        for line in f:
            results.add(line.replace('\n', ''))
    return results


def set_to_file(links, file_name):
    with open(file_name, "w") as f:
        for l in sorted(links):
            f.write(l+"\n")


def get_domain_name(url):
    try:
        results = get_sub_domain_name(url).split('.')
        return results[-2] + '.' + results[-1]
    except Exception as e:
        print(str(e))
        return ''


def get_sub_domain_name(url):
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception as e:
        print(str(e))
        print('[-]Not a valid url.')
