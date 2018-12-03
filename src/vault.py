#!/usr/bin/env python

import argparse
import sys


""" This is the beginning point for VAULT Scanner.

    OPTIONS ->

    1. Scan a website for the following - 1. XSS
                                          2. LFI
                                          3. RFI
                                          4. SQLi

    2. Common header erros : 1. Clickjacking
                             2. jQuery
                             3. Insecure cookie flags
                             4. Session fixation through a cookie injection
                             5. Spoofing Agents
                             6. Brute force login through authorization header
                             7. Testing HTTP methods
                             8. Insecure headers

    3. Collecting data :  1. Port scanning
                          2. Header grabbing
                          3. Banner grabbing
                          4. Finding comments in source code
                          5. Smartwhois scan*
                          6. Check if error handling is done or not and extract the site data using that information
                          7. OS Scanning

    4. SSL scanner

    5. Crawl a website and collect all the url related fields

    6. Scrap a website and collect all the images

    7. URL fuzzing

    8. Shellshock checking
"""

if __name__ == '__main__':

    print(""" ____   _________   ____ ___.____  ___________
\   \ /   /  _  \ |    |   \    | \__    ___/
 \   Y   /  /_\  \|    |   /    |   |    |
  \     /    |    \    |  /|    |___|    |
   \___/\____|__  /______/ |_______ \____|
                \/                 \/         """)

    print("\nWelcome to Vault Scanner\n")

    # Taking in arguments
    parser = argparse.ArgumentParser(description="VAULT Scanner")

    parser.add_argument('-u', '--url', help='URL for scanning')
    parser.add_argument('-p', '--port', action='store_true', help='Port for scanning')
    parser.add_argument('-sp', '--start_port', action='store_true', help='Start port for scanning')
    parser.add_argument('-ep', '--end_port', action='store_true', help='End port for scanning')
    parser.add_argument('-ssl', action='store_true', help='perform SSL scan')
    parser.add_argument('-info', action='store_true', help='Gather information')
    parser.add_argument('-comment', action='store_true', help='Finding comments')
    parser.add_argument('-fuzz', action='store_true', help='Fuzzing URL')
    parser.add_argument('-ip','--ip', help='IP address for port scanning')
    parser.add_argument('-t', '--threads', help='Number of threads to use')
    parser.add_argument('-source_port', help='Source port for sending packets')
    parser.add_argument('-fin', action='store_true', help='Perform FIN Scan')
    parser.add_argument('-null', action='store_true', help='Perform NULL Scan')
    parser.add_argument('-ack', action='store_true', help='Perform TCP ACK Scan')
    parser.add_argument('-xmas', action='store_true', help='Perform XMAS Scan')
    parser.add_argument('-c', '--crawl', action='store_true', help='Crawl and collect all the links')
    parser.add_argument('-xss', action='store_true', help='Scan for XSS vulnerabilities')

    # Print help message if no argumnents are supplied
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if not args.start_port:
        start_port = None
    if not args.end_port:
        end_port = None
    if not args.source_port:
        source_port = None
    if not args.threads:
        threads = None

    if args.ssl:
        if not args.url:
            print('[-] Please enter an URL for SSL scanning')
            sys.exit(1)
        try:
            from lib.ssl_scanner import ssl_scanner
            print('\n--SSL scan using SSL Labs API--\n')

            data = ssl_scanner.analyze(args.url)
            ssl_scanner.vulnerability_parser(data)
        except ImportError:
            print('[-] Could not import the required module.')
        except Exception as e:
            print(e)

    if args.info:
        if not args.url:
            print('[-] Please enter an URl for information gathering')
            sys.exit(1)
        try:
            from lib.info_gathering import header_vuln
            print('[+] Performing informatio gathering over : {}'.format(args.url))

            infoGatherObj = header_vuln.HeaderVuln(args.url)
            infoGatherObj.gather_header()
            infoGatherObj.insecure_cookies()
            infoGatherObj.test_http_methods()
        except ImportError:
            print('[-] Could not import the required module.')
        except Exception as e:
            print(e)

    if args.comment:
        if not args.url:
            print('[-] Please enter an URL for finding comments')
            sys.exit(1)
        try:
            from lib.info_gathering import finding_comment
            print('[+] Performing comment gathering over : {}'.format(args.url))

            findCommnentObj = finding_comment.FindingComments(args.url)
            findCommnentObj.parse_comments()

        except ImportError:
            print('[-] Could not import the required module.')
        except Exception as e:
            print(e)

    if args.fuzz:
        if not args.url:
            print('[-] Please enter an URL for fuzzing')
            sys.exit(1)
        try:
            from lib.fuzzer import fuzzer
            print('[+] Performing fuzzing on : {}'.format(args.url))
            fuzzObj = fuzzer.Fuzzer(base_url=args.url)
            fuzzObj.initiate()

        except ImportError:
            print('[-] Could not import the required module.')
        except Exception as e:
            print(e)

    if args.fin:
        if not args.ip:
            print('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            print('\nInitiating FIN Scan')

            from lib.network_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=start_port, end_port=end_port, threads=threads)
            portScanObj.fin_scan()
        except ImportError:
            print('[-] Could not import the required module')
            sys.exit(1)
        except Exception as e:
            print(e)

    if args.null:
        if not args.ip:
            print('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            print('\nInitiating NULL Scan')

            from lib.network_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=start_port, end_port=end_port, threads=threads)
            portScanObj.null_scan()
        except ImportError:
            print('[-] Could not import the required module.')
            sys.exit(1)
        except Exception as e:
            print(e)

    if args.ack:
        if not args.ip:
            print('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            print('\nInitiating TCP ACK Scan')

            from lib.network_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=start_port, end_port=end_port, threads=threads)
            portScanObj.tcp_ack_scan()
        except ImportError:
            print('[-] Could not import the required module.')
        except Exception as e:
            print(e)

    if args.xmas:
        if not args.ip:
            print('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            print('\nInitiating XMAS Scan')

            from lib.network_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=start_port, end_port=end_port, threads=threads)
            portScanObj.xmas_scan()
        except ImportError:
            print('[-] Could not import the required module.')
            sys.exit(1)
        except Exception as e:
            print(e)
