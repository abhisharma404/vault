from os.path import join
from requests import get, exceptions
from vault_cli import errors

KEY = "pbH1pWMDojANOVHMmeaQUEzvOBspFp0b"  # Shodan.io key
API = "https://api.shodan.io/labs/honeyscore/"


def honeypot(ip):
    url = "https://api.shodan.io/labs/honeyscore/{ip}?key={key}"\
        .format(ip=ip, key=KEY)
    try:
        response = get(url)
        response.raise_for_status()
        result = response.json()
    except exceptions.HTTPError as e:
        blocked = e.response is not None and \
            e.response.status_code in (401, 403, 429)
        errors.report_error(str(e), exc=e,
                            code='E4002' if blocked else 'E4001')
        return
    except (exceptions.RequestException, ValueError) as e:
        errors.report_error(str(e), exc=e, code='E4001')
        return
    if result:
        probability = int(result*10)
        print('Honeypot Probabilty: %s%' % (probability))
    else:
        print('Looks like a Real System')
