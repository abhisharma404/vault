from os.path import join
from requests import get

KEY = "pbH1pWMDojANOVHMmeaQUEzvOBspFp0b" #Shodan.io key
API = "https://api.shodan.io/labs/honeyscore/"

def honeypot(ip):
    url = "https://api.shodan.io/labs/honeyscore/{ip}?key={key}".format(ip=ip, key=KEY)
    result = get(url).json()
    if result:
        probability = int(result*10)
        print('Honeypot Probabilty: %s%' % (probability))
    else:
        print('Looks like a Real System')
