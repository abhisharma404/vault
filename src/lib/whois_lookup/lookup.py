from warnings import filterwarnings
from ipwhois import IPWhois

# To stop the deprecated warnings from ipwhoi package
filterwarnings(action="ignore")


def whois_lookup(ip):
    """Perform Whois lookup for a given IP
        :ip: Ip to peform whois lookup
    """
    obj = IPWhois(ip)
    response = obj.lookup_whois()
    details = response['nets'][0]
    name = details['name']
    city = details['city']
    state = details['state']
    country = details['country']
    address = details['address']
    description = details['description']

    return {'Name': name, 'City': city, 'State': state,
            'Country': country, 'address': address, 'description': description}
