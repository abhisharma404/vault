import sys
import requests

FILE = "payloads/ORV_payload.txt"


def load_payload():
    try:
        with open(FILE, encoding="utf8") as wlf:
            content = wlf.read().splitlines()
        return content
    except FileNotFoundError:
        sys.exit("Couldn't find wordlist file!")


def ORVT(domain):
    """Perform Open redirect vulnerability test
        :domain: URL to Perform the ORV test
    """
    payloads = load_payload()

    for payload in payloads:
        url = domain + payload
        print(url)
        response = requests.get(url, verify=True)
        if response.history:
            print("Request was redirected")
            print("Maybe vulnerable to following payload: %s" % payload)
            print("Final destination:", response.url)
            return

    print("Given domain not vulnerable to any existing payload")
