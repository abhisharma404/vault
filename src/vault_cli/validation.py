"""Input validation helpers."""

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
    """Validate an IPv4 address, exiting with an error if invalid."""
    if re.match(IPV4_RE, ip):
        return ip
    errors.report_error('Please enter a valid IP address')
    sys.exit(1)


def check_ip_range(ip_start_range, ip_end_range):
    """Validate an IP range, exiting with an error if invalid."""
    try:
        ip_start_range = int(ip_start_range)
        ip_end_range = int(ip_end_range)
    except ValueError:
        errors.report_error('Please enter a valid number for the IP range')
        sys.exit(1)
    else:
        if ip_start_range > 0 and ip_end_range < 255 and \
                ip_start_range < ip_end_range:
            return ip_start_range, ip_end_range
        errors.report_error('Please enter a valid IP range')
        sys.exit(1)


def check_root():
    """Return True when running as root, otherwise exit with an error."""
    if hasattr(os, 'getuid') and os.getuid() == 0:
        return True
    errors.report_error('Please start with root privileges')
    sys.exit(1)


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
