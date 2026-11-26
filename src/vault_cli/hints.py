"""Human-readable hints for common scan and attack failures.

Other parts of the CLI call :func:`hint_for` to turn an exception (or an
error string) into a one-sentence, actionable suggestion shown after the
error message.  This module is stdlib-only and import-light so it can be
loaded without network access or third-party packages.

``HINTS`` is an ordered sequence of ``(pattern, hint)`` pairs.  Matching
is a case-insensitive substring test against the exception's type name
and string form; the first matching pattern wins, so more specific
patterns are listed first.
"""

from typing import Optional

# Ordered (pattern, hint) pairs.  Patterns are matched as lowercase
# substrings, so keep them lowercase and put specific cases first.
HINTS = (
    # SSL Labs specifics (before any generic match can steal them).
    ('ip addresses are not allowed',
     'SSL Labs cannot scan IP addresses; provide a hostname.'),
    ('cannot scan ip',
     'SSL Labs cannot scan IP addresses; provide a hostname.'),
    ('ssl labs',
     'SSL Labs could not analyze this target; check that the hostname is public and reachable.'),
    ('blacklisted',
     'This hostname is blacklisted by SSL Labs and cannot be scanned.'),
    # Anti-bot / rate limiting on third-party services.
    ('unusual traffic',
     'The remote service blocked automated requests; wait a while and retry.'),
    ('script blocked',
     'The remote service blocked automated requests; wait a while and retry.'),
    ('rate limit',
     'The remote service is rate-limiting requests; wait and retry.'),
    ('429',
     'The remote service is rate-limiting requests; wait and retry.'),
    # Third-party API changed its response format.
    ('drownvulnerable',
     'The third-party API changed its response format; results may be incomplete.'),
    ('keyerror',
     'The third-party API changed its response format; results may be incomplete.'),
    # JSON parsing failures.
    ('expecting value',
     'The remote service returned non-JSON data (possibly blocked or rate-limited); try again later.'),
    ('jsondecodeerror',
     'The remote service returned non-JSON data (possibly blocked or rate-limited); try again later.'),
    # Malformed URL.
    ('no connection adapters',
     'The generated URL was invalid; check the target URL.'),
    # DNS / network reachability (specific DNS messages before the
    # generic getaddrinfo/gaierror matches).
    ('nodename nor servname',
     'DNS resolution failed; check the hostname and try a different DNS server.'),
    ('name resolution',
     'DNS resolution failed; check the hostname and try a different DNS server.'),
    ('name or service not known',
     'Check your network connection and that the hostname is correct.'),
    ('getaddrinfo',
     'Check your network connection and that the hostname is correct.'),
    ('gaierror',
     'Check your network connection and that the hostname is correct.'),
    ('max retries exceeded',
     'The target could not be reached after several attempts; check connectivity and retry later.'),
    ('connectionerror',
     'Check your network connection and that the hostname is correct.'),
    ('connection refused',
     'The port is closed or the service rejected the connection; verify the target and port.'),
    ('connectionrefusederror',
     'The port is closed or the service rejected the connection; verify the target and port.'),
    ('connection reset',
     'The connection was reset; the target may be dropping packets or blocking the scan.'),
    ('connectionreseterror',
     'The connection was reset; the target may be dropping packets or blocking the scan.'),
    ('reset by peer',
     'The connection was reset; the target may be dropping packets or blocking the scan.'),
    # Timeouts.
    ('timed out',
     'The host did not respond in time; retry, or scan a reachable host.'),
    ('timeout',
     'The host did not respond in time; retry, or scan a reachable host.'),
    # TLS / certificate problems (before the generic "root" pattern).
    # NOTE: no bare 'ssl' pattern here — it would also match "SSL Labs"
    # messages and give them the wrong hint.
    ('certificate verify',
     'TLS/certificate problem; the site may use an untrusted certificate.'),
    ('sslerror',
     'TLS/certificate problem; the site may use an untrusted certificate.'),
    ('certificate',
     'TLS/certificate problem; the site may use an untrusted certificate.'),
    # CLI argument validation and feature-usage messages.  Placed before the
    # generic "root" / "nmap" / "no such file" / "smtp" / "mac address"
    # matches so those never steal these messages.
    ('interface is required',
     'Provide -i <interface>, e.g. -i en0.'),
    ('mac address and interface',
     'Provide -mac <address> and -i <interface>.'),
    ('username is required',
     'Provide -username <user>.'),
    ('no hash modes selected',
     'Use -md5, -sha1, -sha224, -sha256, -sha512 or -all.'),
    ('invalid page count',
     'Enter an integer page count.'),
    ('invalid port range',
     'Provide -sp <start> and -ep <end> with 0 < start < end < 65536.'),
    ('threads must be',
     'Use a positive integer thread count, e.g. -t 10.'),
    ('invalid thread count',
     'Use a positive integer thread count, e.g. -t 10.'),
    ('whois lookup failed',
     'The WHOIS service may be unreachable; check connectivity and retry.'),
    ('keylogger email settings',
     'Provide -host, -username, -password, -sender and -destination.'),
    ('os scan failed',
     'The target may block nmap probes; verify connectivity and privileges.'),
    ('no links were collected',
     'The crawl found no links; try a different page.'),
    # Privileges.
    ('permission denied',
     'This operation requires root privileges; run with sudo.'),
    ('operation not permitted',
     'This operation requires root privileges; run with sudo.'),
    ('getuid',
     'This operation requires root privileges; run with sudo.'),
    ('root',
     'This operation requires root privileges; run with sudo.'),
    # Missing dependencies.
    ('could not import',
     'Missing dependency; install it with: pip install -r requirements.txt'),
    ('no module named',
     'Missing dependency; install it with: pip install -r requirements.txt'),
    # External tools and bundled resources ("nmap" before "no such file",
    # since a missing nmap binary is reported as FileNotFoundError too).
    ('nmap',
     'The nmap binary was not found; install nmap and make sure it is on your PATH.'),
    ('payloads folder',
     "A payload/resource file is missing; check the repository's src/payloads directory."),
    ('directory does not exist',
     "A payload/resource file is missing; check the repository's src/payloads directory."),
    ('no such file',
     "A payload/resource file is missing; check the repository's src/payloads directory."),
    ('max()',
     'No matching results were found; this is not an error in the target.'),
    # Keylogger email configuration.
    ('smtp',
     'Keylogger email settings are missing; configure the SMTP server, credentials, and recipients first.'),
    # Network interface / ARP.
    ('no such device',
     'The network interface does not exist or is unavailable; check the interface name.'),
    ('mac address',
     'The MAC address could not be resolved; the host may be offline or ARP is filtered.'),
    ('no route to host',
     'The host or port is unreachable; the target may be down or firewalled.'),
    ('unreachable',
     'The host or port is unreachable; the target may be down or firewalled.'),
)


def hint_for(exc) -> Optional[str]:
    """Return an actionable one-sentence hint for ``exc``, or ``None``.

    ``exc`` may be a ``BaseException``, a ``VaultError`` (any error object
    carrying its own ``.hint``), a plain string, or ``None``.  Unknown
    errors return ``None``.
    """
    if exc is None:
        return None

    # An error object that already knows its hint wins outright.
    own_hint = getattr(exc, 'hint', None)
    if own_hint:
        return str(own_hint)

    if isinstance(exc, BaseException):
        haystack = '%s %s' % (type(exc).__name__, exc)
    else:
        haystack = str(exc)

    haystack = haystack.lower()
    for pattern, hint in HINTS:
        if pattern in haystack:
            return hint
    return None
