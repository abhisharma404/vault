"""Command-line argument parsing and dispatch."""

import argparse
import sys

from vault_cli import colors, config, validation
from vault_cli.features import (attacks, crawler, others, scanners, utilities,
                                web)

# Flag attribute names that trigger real work in run().  Modifier flags such
# as -this and the -md5/-sha* hash selectors are intentionally excluded
# because they do nothing on their own.
ACTION_FLAGS = {
    'ssl', 'info', 'comment', 'email', 'fuzz', 'fin', 'null', 'ack', 'xmas',
    'os_scan', 'xss', 'ping_sweep', 'arp', 'lfi', 'whois', 'dork', 'ddos',
    'mac_flood', 'cr', 'cri', 'all', 'admin', 'orv', 'keylogger',
    'arp_spoof', 'jquery', 'ping_death', 'bruteforce', 'hash', 'detect_cms',
    'change_mac', 'honey', 'deauth',
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog='vault',
        description='VAULT — Swiss army knife for hackers. A multi-purpose '
                    'security scanner for websites and networks.',
        epilog='''examples:
  vault -u http://example.com -info -comment -ssl -fuzz
  vault -u http://example.com -xss
  vault -ip 192.168.1.1 -p 80 -t 50
  vault -all -u http://example.com -exclude "lfi xss"
  vault -hash -md5 -dir /path/to/files''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    target = parser.add_argument_group('target options')
    target.add_argument('-u', '--url', help='URL to scan')
    target.add_argument('-ip', '--ip', help='IP address for port scanning')
    target.add_argument('-p', '--port', help='Single port for scanning')
    target.add_argument('-sp', '--start_port',
                        help='Start port for scanning')
    target.add_argument('-ep', '--end_port', help='End port for scanning')
    target.add_argument('-i', '--interface',
                        help='Network interface to use')
    target.add_argument('-source_port',
                        help='Source port for sending packets')
    target.add_argument('-dir', help='Directory to scan')
    target.add_argument('-target_bssid',
                        help='Target BSSID for deauthentication')

    scans = parser.add_argument_group('scan modes')
    scans.add_argument('-ssl', action='store_true', help='Perform SSL scan')
    scans.add_argument('-info', action='store_true',
                       help='Gather information about the target')
    scans.add_argument('-comment', action='store_true',
                       help='Find HTML comments')
    scans.add_argument('-email', action='store_true',
                       help='Find email addresses')
    scans.add_argument('-fuzz', action='store_true',
                       help='Fuzz URLs for hidden resources')
    scans.add_argument('-xss', action='store_true',
                       help='Scan for XSS vulnerabilities')
    scans.add_argument('-this', action='store_true',
                       help='Only scan the given URL, do not crawl')
    scans.add_argument('-lfi', action='store_true',
                       help='Scan for LFI vulnerabilities')
    scans.add_argument('-detect_cms', action='store_true',
                       help='Perform CMS detection')
    scans.add_argument('-jquery', action='store_true',
                       help='Check jQuery version and get vulnerabilities')
    scans.add_argument('-admin', action='store_true',
                       help='Find admin panel on a given domain')
    scans.add_argument('-orv', action='store_true',
                       help='Test for open redirection vulnerability')
    scans.add_argument('-honey', action='store_true',
                       help='Detect honeypot')
    scans.add_argument('-whois', action='store_true',
                       help='Perform a whois lookup of a given IP')
    scans.add_argument('-d', '--dork', help='Perform Google dorking')
    scans.add_argument('-bruteforce', action='store_true',
                       help='Perform brute force attack through '
                            'Authorization headers')
    scans.add_argument('-username', help='Username to login')
    scans.add_argument('-hash', action='store_true',
                       help='Start hash scan')
    scans.add_argument('-md5', action='store_true', help='Scan MD5 hashes')
    scans.add_argument('-sha1', action='store_true', help='Scan SHA1 hashes')
    scans.add_argument('-sha224', action='store_true',
                       help='Scan SHA224 hashes')
    scans.add_argument('-sha256', action='store_true',
                       help='Scan SHA256 hashes')
    scans.add_argument('-sha512', action='store_true',
                       help='Scan SHA512 hashes')
    scans.add_argument('-ping_sweep', action='store_true',
                       help='Perform ICMP echo sweep')
    scans.add_argument('-arp', action='store_true', help='Perform ARP scan')
    scans.add_argument('-ip_start_range',
                       help='Start IP of range for scanning')
    scans.add_argument('-ip_end_range',
                       help='End IP of range for scanning')
    scans.add_argument('-fin', action='store_true', help='Perform FIN scan')
    scans.add_argument('-null', action='store_true',
                       help='Perform NULL scan')
    scans.add_argument('-ack', action='store_true',
                       help='Perform TCP ACK scan')
    scans.add_argument('-xmas', action='store_true',
                       help='Perform XMAS scan')
    scans.add_argument('-os_scan', action='store_true',
                       help='Perform OS detection')
    scans.add_argument('-cr', action='store_true',
                       help='Extract links from a web page')
    scans.add_argument('-cri', action='store_true',
                       help='Extract images from a web page')
    scans.add_argument('-all', action='store_true', help='Run all scans')
    scans.add_argument('-exclude',
                       help='Scans to exclude (space-separated)')

    attack = parser.add_argument_group('attacks')
    attack.add_argument('-ddos', action='store_true',
                        help='Perform DDoS attack')
    attack.add_argument('-mac_flood', action='store_true',
                        help='Perform MAC flooding attack')
    attack.add_argument('-arp_spoof', action='store_true',
                        help='Perform ARP spoofing attack')
    attack.add_argument('-ping_death', action='store_true',
                        help='Perform ping of death attack')
    attack.add_argument('-deauth', action='store_true',
                        help='Perform deauthentication attack')
    attack.add_argument('-interval',
                        help='Interval time for sending packets')

    utility = parser.add_argument_group('utility')
    utility.add_argument('-keylogger', action='store_true',
                         help='Capture keystrokes and send them by email')
    utility.add_argument('-host', help='SMTP host to use')
    utility.add_argument('-password', help='Password to login')
    utility.add_argument('-sender', help='Email to send from')
    utility.add_argument('-destination', help='Email to send to')
    utility.add_argument('-change_mac', action='store_true',
                         help='Change MAC address')
    utility.add_argument('-mac', help='New MAC address')

    output = parser.add_argument_group('output options')
    output.add_argument('-o', '--output', help='Output all data to a file')
    output.add_argument('-t', '--threads', help='Number of threads to use')

    general = parser.add_argument_group('general')
    general.add_argument('-v', '--verbose', action='store_true',
                         help='Show tracebacks on errors')
    general.add_argument('--debug', action='store_true',
                         help='Enable debug output')
    general.add_argument('--version', action='version',
                         version='%(prog)s {}'.format(config.VERSION))

    return parser


def run(args):
    """Dispatch a parsed argument namespace to the requested feature(s)."""
    if args.all:
        if args.url:
            scanners.ssl(args)
            others.info(args)
            others.fuzz(args)
            others.comment(args)
            others.email(args)
            web.xss(args)
            web.lfi(args)
            others.admin_panel(args)
            others.open_redirect(args)

        if args.ip:
            others.whois(args)
            scanners.ping_sweep(args)
            others.detect_honeypot(args)

            if validation.check_root():
                scanners.xmas(args)
                scanners.fin(args)
                scanners.null(args)
                scanners.ack(args)

    if args.honey:
        others.detect_honeypot(args)

    if args.admin:
        others.admin_panel(args)

    if args.orv:
        others.open_redirect(args)

    if args.port:
        args.start_port = args.port
        args.end_port = args.port

    if args.whois:
        others.whois(args)

    if args.ssl:
        scanners.ssl(args)

    if args.info:
        others.info(args)

    if args.fuzz:
        others.fuzz(args)

    if args.comment:
        others.comment(args)

    if args.email:
        others.email(args)

    if args.fin and validation.check_root():
        scanners.fin(args)

    if args.null and validation.check_root():
        scanners.null(args)

    if args.ack and validation.check_root():
        scanners.ack(args)

    if args.xmas and validation.check_root():
        scanners.xmas(args)

    if args.xss:
        web.xss(args)

    if args.ping_sweep:
        scanners.ping_sweep(args)

    if args.os_scan:
        scanners.os_scan(args)

    if args.lfi:
        web.lfi(args)

    if args.ddos:
        attacks.ddos(args)

    if args.mac_flood:
        attacks.mac_flood(args)

    if args.cr:
        crawler.crawl(args)

    if args.cri:
        crawler.scrap(args)

    if args.dork:
        others.dork(args)

    if args.arp:
        scanners.arp_scan(args)

    if args.keylogger:
        utilities.keylogger(args)

    if args.arp_spoof:
        attacks.arp_spoof(args)

    if args.jquery:
        others.jquery(args)

    if args.ping_death:
        attacks.ping_death(args)

    if args.bruteforce:
        others.bruteforce(args)

    if args.hash:
        scanners.hash_scan(args)

    if args.detect_cms:
        others.detect_cms(args)

    if args.change_mac:
        utilities.mac_changer(args)

    if args.deauth:
        attacks.deauth(args)


def main():
    validation.install_signal_handlers()

    config.setup_logging()

    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(2)

    args = parser.parse_args()

    # Print the banner after parse_args so that --help/--version output
    # stays clean.
    print(config.BANNER)
    print("\nWelcome to Vault...!\n")

    from vault_cli import errors
    errors.set_verbosity(args.verbose, args.debug)

    if args.url:
        args.url = validation.check_url(args.url)

    if args.ip:
        args.ip = validation.check_ip(args.ip)

    if args.ip_start_range and args.ip_end_range:
        args.ip_start_range, args.ip_end_range = \
            validation.check_ip_range(args.ip_start_range, args.ip_end_range)
    elif args.ip_start_range or args.ip_end_range:
        errors.report_error('Please enter an IP start range and an IP end '
                            'range')
        sys.exit(2)

    if not any(getattr(args, flag) for flag in ACTION_FLAGS):
        errors.report_error('No action specified. Provide at least one scan '
                            'flag (e.g. -info, -ssl, -xss) or -all.',
                            code='E1006',
                            hint="Run 'vault --help' to list available "
                                 'options.')
        sys.exit(2)

    if args.all and not (args.url or args.ip):
        errors.report_error('-all requires a target: provide -u/--url or '
                            '-ip/--ip.',
                            code='E1006',
                            hint="Run 'vault --help' to list available "
                                 'options.')
        sys.exit(2)

    run(args)

    if errors.had_errors():
        from vault_cli import logging_setup
        colors.info('Errors were logged to: {}'.format(
            logging_setup.get_current_path()))
