"""Input validation for the CLI layer.

Validates command-line inputs (URLs, IP addresses, IP ranges, privileges)
and translates failures into the shared error codes, reporting them through
:func:`vault_cli.errors.report_error` so they are printed and logged in one
place.

Error codes used by this module:

    E1001  invalid IP address
    E1002  invalid IP range
    E1003  URL required
    E1004  IP required
    E1005  root privileges required
    E1006  no action specified
    E1007  start/end IP range both required
    E5001  insufficient privileges (root)
"""

import os
import re
import signal
import sys
from urllib.parse import urlparse

from vault_cli import errors

IPV4_RE = (r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
           r'(\.(?!$)|$)){4}$')


def check_url(url):
    """Ensure a URL has a scheme, prepending ``http://`` when missing."""
    if not urlparse(url).scheme:
        return 'http://' + url
    return url


def check_ip(ip):
    """Validate an IPv4 address, exiting with a usage error if invalid."""
    if re.match(IPV4_RE, ip):
        return ip
    errors.report_error('Please enter a valid IP address', code='E1001')
    sys.exit(2)


def check_ip_range(ip_start_range, ip_end_range):
    """Validate an IP range, exiting with a usage error if invalid."""
    try:
        ip_start_range = int(ip_start_range)
        ip_end_range = int(ip_end_range)
    except ValueError:
        errors.report_error('Please enter a valid number for the IP range',
                            code='E1002')
        sys.exit(2)
    else:
        if ip_start_range > 0 and ip_end_range < 255 and \
                ip_start_range < ip_end_range:
            return ip_start_range, ip_end_range
        errors.report_error('Please enter a valid IP range', code='E1002')
        sys.exit(2)


def check_root():
    """Return True when running as root, otherwise exit with an error."""
    if hasattr(os, 'getuid') and os.getuid() == 0:
        return True
    errors.report_error('This operation requires root privileges',
                        code='E5001', hint='Run the command with sudo/root.')
    sys.exit(1)


def require_url(args):
    """Return a scheme-qualified URL from ``args``, exiting if missing."""
    url = getattr(args, 'url', None)
    if not url:
        errors.report_error('URL required', code='E1003',
                            hint='Provide -u <url>')
        sys.exit(2)
    return check_url(url)


def require_ip(args):
    """Return a validated IP address from ``args``, exiting if missing."""
    ip = getattr(args, 'ip', None)
    if not ip:
        errors.report_error('IP required', code='E1004',
                            hint='Provide -ip <ip>')
        sys.exit(2)
    return check_ip(ip)


_sigint_count = 0


def _handle_sigint(signum, frame):
    global _sigint_count
    _sigint_count += 1
    if _sigint_count >= 2:
        errors.report_error('Vault was interrupted by SIGINT')
    else:
        from vault_cli import colors
        colors.info('Press Ctrl-C once again')
    sys.exit(1)


def install_signal_handlers():
    signal.signal(signal.SIGINT, _handle_sigint)
