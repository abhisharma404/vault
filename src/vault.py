#!/usr/bin/env python
try:
    import re
    import sys
    import os
    import logging
    import argparse
    import logger
    import colors
    from urllib.parse import urlparse
except KeyboardInterrupt:
    sys.stderr = open('err.txt','w')
    print('\nProcess stopped by user.')
"""
>> Validation & misc. functions goes here
"""


def check_url(url: str):
    """Check whether or not URL have a scheme

        :url: URL that is to be checked
    """
    if not urlparse(url).scheme:
        return 'http://' + url

    return url


def check_ip(ip: str):
    """
    Check whether the input IP is valid or not
    """
    if re.match(r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
                '(\.(?!$)|$)){4}$', ip):
        return ip
    else:
        colors.error('Please enter a valid IP address')
        LOGGER.error('[-] Please enter a valid IP address')
        sys.exit(1)


def check_ip_range(ip_start_range: int, ip_end_range: int):
    """
    Check whether the input IP range is valid or not
    """
    try:
        ip_start_range = int(ip_start_range)
        ip_end_range = int(ip_end_range)
    except ValueError:
        colors.error('Please enter a valid number for the IP range')
        LOGGER.error('[-] Please enter a valid number for the IP range')
        sys.exit(1)
    else:
        if ip_start_range > 0 and ip_end_range < 255 and\
           ip_start_range < ip_end_range:
            return ip_start_range, ip_end_range
        else:
            colors.error('Please enter a valid IP range')
            LOGGER.error('[-] Please enter a valid IP range')
            sys.exit(1)


def check_root():
    user = os.getuid()

    if user == 0:
        return True
    else:
        colors.error("Plese start with root privileges")
        sys.exit(1)


"""
>> Attacks function goes here

Traversal : current_tread = threading.current_thread()- attacks
                - arp_spoof
                - ddos
                - deauth
                - disaccociation
                - dns_spoof
                - mac_flood
                - ping_death
"""

# DDoS


def ddos(args):
    if args.url is None and args.ip is None:
        colors.error('Please provide either an IP address or an URL to perform'
                     ' DDoS attack')
        sys.exit(1)
    else:
        try:
            from lib.attacks.ddos import ddos

            ddosObj = ddos.DDoS(url=args.url, ip=args.ip,
                                start_port=args.start_port,
                                end_port=args.end_port, dport=args.port,
                                threads=args.threads, interval=args.interval)
            ddosObj.startAttack()
        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
        except Exception as e:
            print(e)
            LOGGER.error(e)
            sys.exit(1)


def mac_flood(args):
    try:
        from lib.attacks.mac_flood import mac_flood

        mac_floodObj = mac_flood.MACFlood(interface=args.interface)
        mac_floodObj.startAttack()
    except ImportError:
        colors.error('Could not import the required module')
        LOGGER.error('[-] Could not import the required module')
    except Exception as e:
        print(e)
        LOGGER.error(e)
        sys.exit(1)


def arp_spoof(args):
    try:
        from lib.attacks.arp_spoof import arp_spoofer

        arpSpoofObj = arp_spoofer.ARPSpoof(ip=args.ip)
        arpSpoofObj.startSpoof()
    except ImportError:
        colors.error('Could not import the required module')
    except Exception as e:
        print(e)


def ping_death(args):
    try:
        from lib.attacks.ping_death import ping_death

        ping_deathObj = ping_death.pingDeath(ip=args.ip, url=args.url)
        ping_deathObj.startAttack()
    except ImportError:
        colors.error('Could not import the required module')
        LOGGER.error('[-] Could not import the required module')
    except Exception as e:
        print(e)
        LOGGER.error(e)
        sys.exit(1)

def deauth(args):
    try:
        from lib.attacks.deauth import deauth_attack

        deauthObj = deauth_attack.Deauth(interface=args.interface,
                                         target_bssid=args.target_bssid)
        deauthObj.startProcess()
    except ImportError:
        colors.error('Could not import the required module')
        LOGGER.error('[-] Could not import the required module')
    except Exception as e:
        print(e)
        LOGGER.error(e)
        sys.exit(1)


"""
>> Website scanner function goes here

Traversal : - website_scanner
                - lfi
                - rfi
                - sqli
                - xss
"""

# XSS


def xss(args):
    if args.url:
        links = []

        path = os.getcwd() + '/lib/website_scanner/xss'
        sys.path.insert(0, path)

        if args.this:
            colors.success('Performing XSS Vulnerability Scan on : {}'
                           .format(args.url))
            links.append(args.url)
        else:
            colors.success('Collecting all the links, crawling : {}'
                           .format(args.url))

            try:
                import crawler
                crawlObj = crawler.Crawl(url=args.url)
                links = crawlObj.getList()
            except ImportError:
                colors.error('Could not import the required module.')
                LOGGER.error('[-] Could not import the required module.')
            except Exception as e:
                LOGGER.error(e)

        try:
            import xss

            xssScanObj = xss.XSS(url=links, payload_file=os.getcwd() +
                                 '/payloads/xss_payloads.txt')
            xssScanObj.initiateEngine()
        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
            sys.exit(1)
        except Exception as e:
            LOGGER.error(e)
    else:
        colors.error('Please enter an URL for XSS Scanning')
        LOGGER.error('[-] Please enter an URL for XSS Scanning')
        sys.exit(1)


# LFI

def lfi(args):
    if not args.url:
        colors.error('Please enter an URL  for scanning')
        LOGGER.error('[-] Please enter an URL for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating LFI Scan')

        from lib.website_scanner.lfi import lfiEngine
        lfiscanObj = lfiEngine.LFI(url=args.url, payload_path=os.getcwd() +
                                   '/payloads/lfi_payloads.json')
        lfiscanObj.startScanner()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        LOGGER.error(e)


"""
>> Crawler function goes here

Traversal : - crawler
"""

# Crawl


def crawl(args):
    if args.url is None:
        colors.error('Please provide either an URL to perform Crawling')
        sys.exit(1)
    else:
        try:
            from lib.crawler import caller

            name = input('Enter the name of folder:->')
            C = caller.Crawler(url=args.url, pname=name)
            if args.cri is None:
                C.start(return_set=False)
                return ''
            else:
                return C.start(return_set=True)
            print('[X]Crawling completed')

        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
        except Exception as e:
            print(e)
            LOGGER.error(e)
            sys.exit(1)


# Scrape images

def scrap(args):
    if args.url is None:
        colors.error('Please provide URL to perform Scraping')
        sys.exit(1)
    else:
        try:
            from lib.crawler import finder
            links, path = crawl(args)
            finder.initiate(links, path)
            print('[X]Scraping completed')

        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
        except Exception as e:
            print(e)
            LOGGER.error(e)
            sys.exit(1)


"""
>> Other functions goes here

Traversal : - others
                - admin_panel
                - brute force login
                - detect_cms
                - detect_ddos
                - detect_deauth
                - detect_honeypots
                - error_handler
                - fuzzer
                - google_dork
                - info_gathering
                    - finder
                        - finding_email
                        - finding_comment
                    - header_vuln
                    - jquery_check
                - whois_lookup
"""

# Info gathering


def info(args):
    if not args.url:
        colors.error('Please enter an URl for information gathering')
        LOGGER.error('[-] Please enter an URl for information gathering')
        sys.exit(1)
    try:
        from lib.others.info_gathering import header_vuln
        colors.info('Performing information gathering over : {}'
                    .format(args.url))

        infoGatherObj = header_vuln.HeaderVuln(args.url)
        header_data = infoGatherObj.gather_header()
        cookie_data = infoGatherObj.insecure_cookies()
        method_data = infoGatherObj.test_http_methods()

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'
            i = 1

            with open(file, 'w') as f:
                f.write('---[!] Header Details---\n\n')

                for k, v in header_data.items():
                    f.write(str(k) + ' : ' + str(v) + os.linesep)
                f.write('\n---[!] Testing Insecure Cookies---\n\n')

                for k in cookie_data:
                    f.write(k + os.linesep)
                f.write('\n---[!] Testing HTTP methods---\n\n')

                for k in method_data:
                    if i % 3 != 0:
                        f.write(str(k) + ' ')
                    else:
                        f.write(str(k) + os.linesep)
                    i = i + 1

            colors.success('File has been saved successfully')

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


# Finding comments

def comment(args):
    if not args.url:
        colors.error('Please enter an URL for finding comments')
        LOGGER.error('[-] Please enter an URL for finding comments')
        sys.exit(1)
    try:
        from lib.others.info_gathering.finder import finding_comment
        colors.info('Performing comment gathering over : {}'.format(args.url))

        findCommnentObj = finding_comment.FindingComments(args.url)
        comment_dict = findCommnentObj.parse_comments()

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'w') as f:
                f.write('---[!] Comments---\n\n')
                for k, v in comment_dict.items():
                    f.write(str(k) + ' : ' + str(v) + os.linesep)
            colors.success('File has been saved successfully')

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


def email(args):
    if not args.url:
        colors.error('Please enter an URL for finding emails')
        LOGGER.error('[-] Please enter an URL for finding emails')
        sys.exit(1)
    try:
        from lib.others.info_gathering.finder import finding_email
        colors.info('Performing email gathering over : {}'.format(args.url))

        findEmailObj = finding_email.FindingEmails(args.url)
        found_emails = findEmailObj.parse_emails()

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'w') as f:
                f.write('---[!] Emails---\n\n')
                for email in found_emails:
                    f.write(str(email) + os.linesep)
            colors.success('File has been saved successfully')

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)

# Check Jquery version for associated vulnerabilites


def jquery(args):
    if not args.url:
        colors.error('Please enter an URL for jquery checking')
        LOGGER.error('[-] Please enter an URL for jquery checking')
        sys.exit(1)
    try:
        from lib.others.info_gathering import jquery_check

        jquery_checkObj = jquery_check.JqueryCheck(url=args.url)
        jquery_checkObj.start_engine()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)

# Fuzzer


def fuzz(args):
    if not args.url:
        colors.error('Please enter an URL for fuzzing')
        LOGGER.error('[-] Please enter an URL for fuzzing')
        sys.exit(1)
    try:
        from lib.others.fuzzer import fuzzer
        colors.info('Performing fuzzing on : {}'.format(args.url))
        fuzzObj = fuzzer.Fuzzer(base_url=args.url, thread_num=args.threads)
        fuzzObj.initiate()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


# Google dork

def dork(args):
    if args.dork:
        from lib.others.google_dork import dorker
        dorks = args.dork
        page = int(input("\nNumber of Pages to scrap :: \033[1;37m"))
        print('\n\033[1;37m[>]Searching ...\033[1;37m  \n')
        web_lists = dorker.start_dorking(dorks, page)

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'w') as f:
                f.write('Google Dorks results: \n\n')
                for k in web_lists:
                    f.write(str(k) + os.linesep)
            colors.success('File has been saved successfully')


# WHOIS Lookup

def whois(args):
    if not args.ip:
        colors.error('Please enter an IP for Whois lookup')
        LOGGER.error('[-] Please enter an IP for Whois lookup')
        sys.exit(1)
    try:
        from lib.others.whois_lookup import lookup
        data = lookup.whois_lookup(args.ip)

        colors.success('Information after Whois lookup: \n')

        for k, v in data.items():
            print(k, ':', v)

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'w') as f:
                f.write('Information after Whois lookup: \n\n')
                for k, v in data.items():
                    f.write(str(k) + ' : ' + str(v) + os.linesep)
            colors.success('File has been saved successfully')

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


# Admin panel

def admin_panel(args):
    """Find admin panel of a given domain
    """
    if args.url is None:
        colors.error('Please provide either an URL for finding admin panel')
        sys.exit(1)
    else:
        try:
            from lib.others.admin_panel import admin_panel

            admin_panel.find_admin_panel(args.url)
        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
        except Exception as e:
            print(e)
            LOGGER.error(e)
            sys.exit(1)


def bruteforce(args):
    if not args.url:
        colors.error('Please enter an URL for bruteforce')
        LOGGER.error('[-] Please enter an URL for bruteforce')
        sys.exit(1)
    try:
        from lib.others.bruteforce_login import bruteforce_login
        colors.info('Performing bruteforce on : {}'.format(args.url))
        bruteforceObj = bruteforce_login.BruteforceLogin(url=args.url,
                                                         threads=args.threads,
                                                         user=args.username)
        bruteforceObj.startAttack()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)

# try to detect the CMS used in a website


def detect_cms(args):
    if not args.url:
        colors.error('Please enter an URL for CMS detecting')
        LOGGER.error('[-] Please enter an URL for CMS detecting')
        sys.exit(1)
    try:
        from lib.others.detect_cms import detect_cms

        detect_cmsObj = detect_cms.DetectCMS(url=args.url)
        detect_cmsObj.start_engine()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


"""
>> Scanner functions goes here

Traversal : - scanner
                - hash_scanner
                - ip_scanner
                    - ping_sweep
                    - arp_scanner
                - os_scan
                - port_scanner : ACK, FIN, NULL, XMAS
                - ssl_scanner
"""

# Hash scanner


def hash_scan(args):

    LIST_OF_SCANS = []

    if not args.all:
        if args.md5:
            LIST_OF_SCANS.append('md5')
        if args.sha1:
            LIST_OF_SCANS.append('sha1')
        if args.sha224:
            LIST_OF_SCANS.append('sha224')
        if args.sha256:
            LIST_OF_SCANS.append('sha256')
        if args.sha512:
            LIST_OF_SCANS.append('sha512')
    else:
        LIST_OF_SCANS = ['md5', 'sha1', 'sha224', 'sha256', 'sha512']

    if args.exclude:
        to_ignore = [mode for mode in (args.exclude).split(' ')]
        try:
            for mode in to_ignore:
                LIST_OF_SCANS.remove(mode)
        except Exception as e:
            print(e)

    try:
        from lib.scanner.hash_scanner import hash_scanner

        hashScanObj = hash_scanner.HashScanner(list_scans=LIST_OF_SCANS,
                                               threads=args.threads,
                                               file_path=args.dir)
        resultDict = hashScanObj.startScan()

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'wt') as f:
                f.write('[+] Hash Scan Result : \n\n')
                for key, item in resultDict.items():
                    f.write(str(key) + ' : ' + str(item) + os.linesep)

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        print(e)
        LOGGER.error(e)


# IP Scanner

def ack(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        LOGGER.error('[-] Please enter an IP address for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating TCP ACK Scan')

        from lib.scanner.port_scanner import port_scanner

        portScanObj = port_scanner.PortScanner(ip=args.ip,
                                               start_port=args.start_port,
                                               end_port=args.end_port,
                                               threads=args.threads,
                                               source_port=args.source_port)
        portScanObj.tcp_ack_scan()
    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


def fin(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        LOGGER.error('[-] Please enter an IP address for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating FIN Scan')

        from lib.scanner.port_scanner import port_scanner

        portScanObj = port_scanner.PortScanner(ip=args.ip,
                                               start_port=args.start_port,
                                               end_port=args.end_port,
                                               threads=args.threads,
                                               source_port=args.source_port)
        portScanObj.fin_scan()
    except ImportError:
        colors.error('Could not import the required module')
        LOGGER.error('[-] Could not import the required module')
        sys.exit(1)
    except Exception as e:
        LOGGER.error(e)


def null(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        LOGGER.error('[-] Please enter an IP address for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating NULL Scan')

        from lib.scanner.port_scanner import port_scanner

        portScanObj = port_scanner.PortScanner(ip=args.ip,
                                               start_port=args.start_port,
                                               end_port=args.end_port,
                                               threads=args.threads,
                                               source_port=args.source_port)
        portScanObj.null_scan()
    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        LOGGER.error(e)


def xmas(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        LOGGER.error('[-] Please enter an IP address for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating XMAS Scan')

        from lib.scanner.port_scanner import port_scanner

        portScanObj = port_scanner.PortScanner(ip=args.ip,
                                               start_port=args.start_port,
                                               end_port=args.end_port,
                                               threads=args.threads,
                                               source_port=args.source_port)
        portScanObj.xmas_scan()
    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        LOGGER.error(e)


# Port Scanner

def ping_sweep(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        sys.exit(1)
    else:
        try:
            colors.info('Initiating Ping Sweep Scan')

            from lib.scanner.ip_scanner import ping_sweep

            pingSweepObj = ping_sweep.IPScanner(ip=args.ip,
                                                start_ip=args.ip_start_range,
                                                end_ip=args.ip_end_range,
                                                threads=args.threads)
            pingSweepObj.threadingScan()
        except ImportError:
            colors.error('Could not import the required module.')
        except Exception as e:
            print(e)


def arp_scan(args):
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        sys.exit(1)
    else:
        try:
            colors.info('Initiating ARP Scan')

            from lib.scanner.ip_scanner import arp_scanner

            arpScanObj = arp_scanner.ARPScan(ip=args.ip,
                                             start_ip=args.ip_start_range,
                                             end_ip=args.ip_end_range,
                                             threads=args.threads)
            arpScanObj.threadingScan()
        except ImportError:
            colors.error('Could not import the required module.')
        except Exception as e:
            print(e)


# SSL scanner

def ssl(args):
    if not args.url:
        colors.error('Please enter an URL for SSL scanning')
        LOGGER.error('[-] Please enter an URL for SSL scanning')
        sys.exit(1)
    try:
        from lib.scanner.ssl_scanner import ssl_scanner
        colors.info('SSL scan using SSL Labs API')

        data = ssl_scanner.analyze(args.url)
        ssl_data = ssl_scanner.vulnerability_parser(data)

        if args.output:
            if args.output.endswith('.txt'):
                file = args.output
            else:
                file = args.output + '.txt'

            with open(file, 'wt') as f:
                f.write('[+] Vulnerability Scan Result : \n\n')
                for k, v in ssl_data.items():
                    f.write(str(k) + ' : ' + str(v) + os.linesep)

            colors.success('File has been saved successfully')

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)

# OS Scanner


def os_scan(args):
    if args.url is None and args.ip is None:
        colors.error('Please provide either an IP address or an URL to '
                     'perform OS Scan')
        LOGGER.error('[-] Please provide either an IP address or an URL to '
                     'perform OS Scan')
        sys.exit(1)
    try:
        colors.info('OS Scan using Nmap')

        from lib.scanner.os_scan import os_scan

        os_scanObj = os_scan.OSScan(ip=args.ip, url=args.url)
        os_scanObj.os_scan()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
    except Exception as e:
        LOGGER.error(e)


def open_redirect(args):
    if not args.url:
        colors.error('Please enter an URL  for scanning')
        LOGGER.error('[-] Please enter an URL for scanning')
        sys.exit(1)
    else:
        try:
            colors.info("Testing for open redirection Vulnerability")

            from lib.others.open_redirection import redirection
            redirection.ORVT(args.url)

        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
        except Exception as e:
            print(e)
            LOGGER.error(e)
            sys.exit(1)


"""
>> utilities functions goes here

Traversal : - utilities
                - backdoor_generator
                - data_monitor
                - extract_sitemap
                - keylogger
                - mac-changer
                - ssh_tunnel
                - trace_route
"""


def keylogger(args):
    try:
        colors.info('Keylogger starting...')

        from lib.utilities.keylogger import keylogger

        keyloggerObj = keylogger.keylogger(interval=args.interval,
                                           sender=args.sender,
                                           destination=args.destination,
                                           host=args.host, port=args.port,
                                           username=args.username,
                                           password=args.password)
        keyloggerObj.start_keylogger()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)

    except Exception as e:
        LOGGER.error(e)


def mac_changer(args):

    try:
        colors.info('Loading MAC Changer...')

        from lib.utilities.mac_changer import mac_changer

        macObj = mac_changer.MACChanger(mac_addr=args.mac,
                                        interface=args.interface)
        macObj.startProcess()

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)

    except Exception as e:
        print(e)
        LOGGER.error(e)


def detect_honeypot(args):
    """Check if the given ip is a honeypot or not
    """
    if not args.ip:
        colors.error('Please enter an IP address for scanning')
        LOGGER.error('[-] Please enter an IP address for scanning')
        sys.exit(1)
    try:
        colors.info('Detecting honeypot: ')

        from lib.others.detect_honeypots import honeypots

        honeypots.honeypot(args.ip)

    except ImportError:
        colors.error('Could not import the required module.')
        LOGGER.error('[-] Could not import the required module.')
        sys.exit(1)

    except Exception as e:
        print(e)
        LOGGER.error(e)


if __name__ == '__main__':

    try:
        print(""" ____   _________   ____ ___.____  ___________
\   \ /   /  _  \ |    |   \    | \__    ___/
 \   Y   /  /_\  \|    |   /    |   |    |
  \     /    |    \    |  /|    |___|    |
   \___/\____|__  /______/ |_______ \____|
                \/                 \/         """)
        print("\nWelcome to Vault...!\n")

        log_file_name = os.path.join(os.getcwd(), "vault.log")
        logger.Logger.create_logger(log_file_name, __package__)
        LOGGER = logging.getLogger(__name__)

        # Taking in arguments
        parser = argparse.ArgumentParser(description="VAULT")

        parser.add_argument('-u', '--url', help='URL for scanning')
        parser.add_argument('-p', '--port', help='Single port for scanning')
        parser.add_argument('-sp', '--start_port', help='Start port for scanning')
        parser.add_argument('-ep', '--end_port', help='End port for scanning')
        parser.add_argument('-ssl', action='store_true', help='perform SSL scan')
        parser.add_argument('-info', action='store_true',
                            help='Gather information')
        parser.add_argument('-comment', action='store_true',
                            help='Finding comments')
        parser.add_argument('-email', action='store_true', help='Finding emails')
        parser.add_argument('-fuzz', action='store_true', help='Fuzzing URL')
        parser.add_argument('-ip', '--ip', help='IP address for port scanning')
        parser.add_argument('-t', '--threads', help='Number of threads to use')
        parser.add_argument('-i', '--interface',
                            help='Networking Interface to use')
        parser.add_argument('-source_port', help='Source port for sending packets')
        parser.add_argument('-fin', action='store_true', help='Perform FIN Scan')
        parser.add_argument('-null', action='store_true', help='Perform NULL Scan')
        parser.add_argument('-ack', action='store_true',
                            help='Perform TCP ACK Scan')
        parser.add_argument('-xmas', action='store_true', help='Perform XMAS Scan')
        parser.add_argument('-os_scan', action='store_true',
                            help='Perform OS Scan')
        parser.add_argument('-xss', action='store_true',
                            help='Scan for XSS vulnerabilities')
        parser.add_argument('-this', action='store_true',
                            help='Only scan the given URL, do not crawl')
        parser.add_argument('-ping_sweep', action='store_true',
                            help='ICMP ECHO request')
        parser.add_argument('-arp', action='store_true', help='ARP Scan')
        parser.add_argument('-ip_start_range', help='Start range for scanning IP')
        parser.add_argument('-ip_end_range', help='End range for scanning IP')
        parser.add_argument('-lfi', action='store_true',
                            help='Scan for LFI vulnerabilities')
        parser.add_argument('-whois', action='store_true',
                            help='perform a whois lookup of a given IP')
        parser.add_argument('-o', '--output', help='Output all data')
        parser.add_argument('-d', '--dork', help='Perform google dorking')
        parser.add_argument('-ddos', action='store_true',
                            help='Perform DDoS attack')
        parser.add_argument('-mac_flood', action='store_true',
                            help='Perform MAC Flooding attack')
        parser.add_argument('-interval', help='Interval time for sending packets')
        parser.add_argument('-cr', action='store_true',
                            help='For extracting links from a web page')
        parser.add_argument('-cri', action='store_true',
                            help='For extracting images from a Web page')
        parser.add_argument('-all', action='store_true', help='Run all scans')
        parser.add_argument('-exclude', help='Scans to exclude')
        parser.add_argument('-admin', action='store_true',
                            help='Find admin panel on a given domain')
        parser.add_argument('-orv', action='store_true',
                            help='Test for open redirection Vulnerability')
        parser.add_argument('-keylogger', action='store_true',
                            help='Capture keystrokes and send them by email')
        parser.add_argument('-host', help='SMTP Host to use')
        parser.add_argument('-username', help='Username to login')
        parser.add_argument('-password', help='Password to login')
        parser.add_argument('-sender', help='Email to send from')
        parser.add_argument('-destination', help='Email to send to')
        parser.add_argument('-arp_spoof', action='store_true', help='ARP Spoofing')
        parser.add_argument('-jquery', action='store_true',
                            help='Check jQuery version and get vulnerabilities')
        parser.add_argument('-ping_death', action='store_true',
                            help='Perform ping of death attack')
        parser.add_argument('-bruteforce', action='store_true',
                            help='Perform brute force attack through Authorization'
                                'headers')
        parser.add_argument('-hash', action='store_true', help='Start hash scan')
        parser.add_argument('-md5', action='store_true', help='Scan MD5')
        parser.add_argument('-sha1', action='store_true', help='Scan SHA1')
        parser.add_argument('-sha224', action='store_true', help='Scan SHA224')
        parser.add_argument('-sha256', action='store_true', help='Scan SHA256')
        parser.add_argument('-sha512', action='store_true', help='Scan SHA512')
        parser.add_argument('-dir', help='Directory to scan')
        parser.add_argument('-detect_cms', action='store_true',
                            help='Perform CMS Detection')
        parser.add_argument('-change_mac', action='store_true',
                            help='Chnage MAC address')
        parser.add_argument('-mac', help='New MAC address')
        parser.add_argument('-honey', action='store_true', help='Detect honeypot')
        parser.add_argument('-target_bssid', help='Target BSSID')
        parser.add_argument('-deauth', action='store_true', help='De-authentication attack')

        colors.info("Please Check log file for information about any errors")

        # Print help message if no arguments are supplied
        if len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(1)

        args = parser.parse_args()

        if args.url:
            args.url = check_url(args.url)

        if args.ip:
            args.ip = check_ip(args.ip)

        if args.ip_start_range and args.ip_end_range:
            args.ip_start_range, args.ip_end_range = \
                check_ip_range(args.ip_start_range, args.ip_end_range)
        elif args.ip_start_range or args.ip_end_range:
            colors.error('Please enter an IP start range and an IP end range')
            LOGGER.error('[-] Please enter an IP start range and an IP end range')
            sys.exit(1)

        if args.all:
            if args.url:
                ssl(args)
                info(args)
                fuzz(args)
                comment(args)
                email(args)
                xss(args)
                lfi(args)
                admin_panel(args)
                open_redirect(args)

            if args.ip:
                whois(args)
                ping_sweep(args)
                detect_honeypot(args)

                if check_root():
                    xmas(args)
                    fin(args)
                    null(args)
                    ack(args)

        if args.honey:
            detect_honeypot(args)

        if args.admin:
            admin_panel(args)

        if args.orv:
            open_redirect(args)

        if args.port:
            args.start_port = args.port
            args.end_port = args.port

        if args.whois:
            whois(args)

        if args.ssl:
            ssl(args)

        if args.info:
            info(args)

        if args.fuzz:
            fuzz(args)

        if args.comment:
            comment(args)

        if args.email:
            email(args)

        if args.fin and check_root():
            fin(args)

        if args.null and check_root():
            null(args)

        if args.ack and check_root():
            ack(args)

        if args.xmas and check_root():
            xmas(args)

        if args.xss:
            xss(args)

        if args.ping_sweep:
            ping_sweep(args)

        if args.os_scan:
            os_scan(args)

        if args.lfi:
            lfi(args)

        if args.ddos:
            ddos(args)

        if args.mac_flood:
            mac_flood(args)

        if args.cr:
            crawl(args)

        if args.cri:
            scrap(args)

        if args.dork:
            dork(args)

        if args.arp:
            arp_scan(args)

        if args.keylogger:
            keylogger(args)

        if args.arp_spoof:
            arp_spoof(args)

        if args.jquery:
            jquery(args)

        if args.ping_death:
            ping_death(args)

        if args.bruteforce:
            bruteforce(args)

        if args.hash:
            hash_scan(args)

        if args.detect_cms:
            detect_cms(args)

        if args.change_mac:
            mac_changer(args)

        if args.deauth:
            deauth(args)
    except KeyboardInterrupt:
        sys.stderr = open('err.txt','w')
        print('\nProcess stopped by user.')
