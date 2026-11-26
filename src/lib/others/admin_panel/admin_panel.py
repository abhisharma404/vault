import sys
import requests
import colors
from vault_cli import errors

FILE = "payloads/admin_payload.txt"


def load_list():
    try:
        with open(FILE, encoding="utf8") as wlf:
            content = wlf.read().splitlines()
        return content

    except FileNotFoundError:
        errors.report_error("Couldn't find wordlist file!", code='E6002')
        sys.exit(1)


def find_admin_panel(domain):
    """Find admin panel on a given domain
        :domain: URL to the website on which file is to be searched
    """
    found = []
    reported = False

    print("Loading admin page list...")
    urls = load_list()

    for link in urls:
        site = domain + "/" + link

        print("Trying: %s" % site)
        try:
            req = requests.get(site)
        except requests.exceptions.RequestException as e:
            if not reported:
                errors.report_error('Admin panel scan request failed',
                                    exc=e, code='E2001')
                reported = True
            continue

        if req.status_code == 200:
            found.append(site)
            print("%s page valid!" % site)

    find_robots(domain, reported)


def find_robots(domain, reported=False):
    """Try to find robots.txt file on a given domain
        :domain: URL to the website on which file is to be searched
    """
    print("Attempting to get robots.txt file...")
    robo = domain + "/robots.txt"
    try:
        req = requests.get(robo)
    except requests.exceptions.RequestException as e:
        if not reported:
            errors.report_error('Robots.txt request failed', exc=e,
                                code='E2001')
        return

    if req.status_code == 200:
        print("robots.txt found!")
        try:
            content = req.content.decode('utf-8')
        except UnicodeDecodeError:
            colors.warning('Could not decode robots.txt content as UTF-8.')
            return
        print(content.strip())

        print("content of robots.txt is: ")
    else:
        print("Robots.txt not found!")
