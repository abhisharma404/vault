#! /usr/bin/python

from warnings import filterwarnings
from ipwhois import IPWhois
import colors
from vault_cli import errors


# To stop the deprecated warnings from ipwhoi package
filterwarnings(action="ignore")


def whois_lookup(ip):
    """Perform Whois lookup for a given IP
        :ip: Ip to peform whois lookup
    """
    colors.info('Performing WHOIS lookup')
    try:
        obj = IPWhois(ip)
        response = obj.lookup_whois()
        details = response['nets'][0]
        name = details['name']
        city = details['city']
        state = details['state']
        country = details['country']
        address = details['address']
        description = details['description']
    except ValueError as e:
        # ipwhois raises ValueError('IP is not defined') for bad input.
        errors.report_error('WHOIS lookup failed', exc=e, code='E1004')
        return {}
    except Exception as e:
        errors.report_error('WHOIS lookup failed', exc=e, code='E4001')
        return {}

    return {'Name': name, 'City': city, 'State': state,
            'Country': country, 'address': address, 'description': description}
