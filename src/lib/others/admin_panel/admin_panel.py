import sys
import requests

FILE = "payloads/admin_payload.txt"


def load_list():
    try:
        with open(FILE, encoding="utf8") as wlf:
            content = wlf.read().splitlines()
        return content

    except FileNotFoundError:
        sys.exit("Couldn't find wordlist file!")


def find_admin_panel(domain):
    """Find admin panel on a given domain
        :domain: URL to the website on which file is to be searched
    """
    found = []

    print("Loading admin page list...")
    urls = load_list()

    for link in urls:
        site = domain + "/" + link

        print("Trying: %s" % site)
        req = requests.get(site)

        if req.status_code == 200:
            found.append(site)
            print("%s page valid!" % site)

    find_robots(domain)


def find_robots(domain):
    """Try to find robots.txt file on a given domain
        :domain: URL to the website on which file is to be searched
    """
    print("Attempting to get robots.txt file...")
    robo = domain + "/robots.txt"
    req = requests.get(robo)

    if req.status_code == 200:
        print("robots.txt found!")
        content = req.content.decode('utf-8')
        print(content.strip())

        print("content of robots.txt is: ")
    else:
        print("Robots.txt not found!")
