#!/usr/bin/env python

import argparse
import logging
import sys
import os
import logger
from urllib.parse import urlparse
import colors

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


def check_URL(url: str):
    """Check whether or not URL have a scheme

        :url: URL that is to be checked
    """
    if not urlparse(url).scheme:
        return 'http://' + url

    return url


if __name__ == '__main__':

    print(""" ____   _________   ____ ___.____  ___________
\   \ /   /  _  \ |    |   \    | \__    ___/
 \   Y   /  /_\  \|    |   /    |   |    |
  \     /    |    \    |  /|    |___|    |
   \___/\____|__  /______/ |_______ \____|
                \/                 \/         """)

    print("\nWelcome to Vault Scanner!\n")

    log_file_name = os.path.join(os.getcwd(), "vault-scanner.log")
    logger.Logger.create_logger(log_file_name, __package__)
    LOGGER = logging.getLogger(__name__)

    # Taking in arguments
    parser = argparse.ArgumentParser(description="VAULT Scanner")

    parser.add_argument('-u', '--url', help='URL for scanning')
    parser.add_argument('-p', '--port', help='Single port for scanning')
    parser.add_argument('-sp', '--start_port', help='Start port for scanning')
    parser.add_argument('-ep', '--end_port', help='End port for scanning')
    parser.add_argument('-ssl', action='store_true', help='perform SSL scan')
    parser.add_argument('-info', action='store_true', help='Gather information')
    parser.add_argument('-comment', action='store_true', help='Finding comments')
    parser.add_argument('-fuzz', action='store_true', help='Fuzzing URL')
    parser.add_argument('-ip', '--ip', help='IP address for port scanning')
    parser.add_argument('-t', '--threads', help='Number of threads to use')
    parser.add_argument('-source_port', help='Source port for sending packets')
    parser.add_argument('-fin', action='store_true', help='Perform FIN Scan')
    parser.add_argument('-null', action='store_true', help='Perform NULL Scan')
    parser.add_argument('-ack', action='store_true', help='Perform TCP ACK Scan')
    parser.add_argument('-xmas', action='store_true', help='Perform XMAS Scan')
    parser.add_argument('-c', '--crawl', action='store_true', help='Crawl and collect all the links')
    parser.add_argument('-xss', action='store_true', help='Scan for XSS vulnerabilities')
    parser.add_argument('-this', action='store_true', help='Only scan the given URL, do not crawl')
    parser.add_argument('-ping_sweep', action='store_true', help='ICMP ECHO request')
    parser.add_argument('-ip_start_range', help='Start range for scanning IP')
    parser.add_argument('-ip_end_range', help='End range for scanning IP')
    parser.add_argument('-lfi', action='store_true', help='Scan for LFI vulnerabilities')

    colors.success("Please Check log file for information about any errors")

    # Print help message if no argumnents are supplied
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.url:
        args.url = check_URL(args.url)

    if args.port:
        args.start_port = args.port
        args.end_port = args.port

    if args.ssl:
        if not args.url:
            colors.error('Please enter an URL for SSL scanning')
            LOGGER.error('[-] Please enter an URL for SSL scanning')
            sys.exit(1)
        try:
            from lib.ssl_scanner import ssl_scanner
            colors.info('SSL scan using SSL Labs API')

            data = ssl_scanner.analyze(args.url)
            ssl_scanner.vulnerability_parser(data)
        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
        except Exception as e:
            LOGGER.error(e)

    if args.info:
        if not args.url:
            colors.error('Please enter an URl for information gathering')
            LOGGER.error('[-] Please enter an URl for information gathering')
            sys.exit(1)
        try:
            from lib.info_gathering import header_vuln
            colors.success('Performing information gathering over : {}'.format(args.url))

            infoGatherObj = header_vuln.HeaderVuln(args.url)
            infoGatherObj.gather_header()
            infoGatherObj.insecure_cookies()
            infoGatherObj.test_http_methods()
        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
        except Exception as e:
            LOGGER.error(e)

    if args.comment:
        if not args.url:
            colors.error('Please enter an URL for finding comments')
            LOGGER.error('[-] Please enter an URL for finding comments')
            sys.exit(1)
        try:
            from lib.info_gathering import finding_comment
            colors.success('Performing comment gathering over : {}'.format(args.url))

            findCommnentObj = finding_comment.FindingComments(args.url)
            findCommnentObj.parse_comments()

        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
        except Exception as e:
            LOGGER.error(e)

    if args.fuzz:
        if not args.url:
            colors.error('Please enter an URL for fuzzing')
            LOGGER.error('[-] Please enter an URL for fuzzing')
            sys.exit(1)
        try:
            from lib.fuzzer import fuzzer
            colors.success('Performing fuzzing on : {}'.format(args.url))
            fuzzObj = fuzzer.Fuzzer(base_url=args.url, thread_num=args.threads)
            fuzzObj.initiate()

        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
        except Exception as e:
            LOGGER.error(e)

    if args.fin:
        if not args.ip:
            colors.error('Please enter an IP address for scanning')
            LOGGER.error('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            colors.info('Initiating FIN Scan')

            from lib.port_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=args.start_port,
                                                   end_port=args.end_port, threads=args.threads,
                                                   source_port=args.source_port)
            portScanObj.fin_scan()
        except ImportError:
            colors.error('Could not import the required module')
            LOGGER.error('[-] Could not import the required module')
            sys.exit(1)
        except Exception as e:
            LOGGER.error(e)

    if args.null:
        if not args.ip:
            colors.error('Please enter an IP address for scanning')
            LOGGER.error('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            colors.info('Initiating NULL Scan')

            from lib.port_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=args.start_port,
                                                   end_port=args.end_port, threads=args.threads,
                                                   source_port=args.source_port)
            portScanObj.null_scan()
        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
            sys.exit(1)
        except Exception as e:
            LOGGER.error(e)

    if args.ack:
        if not args.ip:
            colors.error('Please enter an IP address for scanning')
            LOGGER.error('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            colors.info('Initiating TCP ACK Scan')

            from lib.port_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=args.start_port,
                                                   end_port=args.end_port, threads=args.threads,
                                                   source_port=args.source_port)
            portScanObj.tcp_ack_scan()
        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
        except Exception as e:
            LOGGER.error(e)

    if args.xmas:
        if not args.ip:
            colors.error('Please enter an IP address for scanning')
            LOGGER.error('[-] Please enter an IP address for scanning')
            sys.exit(1)
        try:
            colors.info('Initiating XMAS Scan')

            from lib.port_scanner import port_scanner

            portScanObj = port_scanner.PortScanner(ip=args.ip, start_port=args.start_port,
                                                   end_port=args.end_port, threads=args.threads,
                                                   source_port=args.source_port)
            portScanObj.xmas_scan()
        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
            sys.exit(1)
        except Exception as e:
            LOGGER.error(e)

    if args.xss:
        if args.url:
            links = []

            path = os.getcwd() + '/lib/website_scanner/xss'
            sys.path.insert(0, path)

            if args.this:
                colors.success('Performing XSS Vulnerability Scan on : {}'.format(args.url))
                links.append(args.url)
            else:
                colors.success('Collecting all the links, crawling : {}'.format(args.url))

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

                xssScanObj = xss.XSS(url=links,
                                     payload_file=os.getcwd()+'/payloads/xss_payloads.txt')
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

    if args.ping_sweep:
        if not args.ip:
            colors.error('Please enter an IP address for scanning')
            sys.exit(1)
        else:
            try:
                colors.info('Initiating Ping Sweep Scan')

                from lib.ip_scanner import ping_sweep

                pingSweepObj = ping_sweep.IPScanner(ip=args.ip,
                                                    start_ip=args.ip_start_range,
                                                    end_ip=args.ip_end_range,
                                                    threads=args.threads)
                pingSweepObj.threadingScan()
            except ImportError:
                colors.error('Could not import the required module.')
            except Exception as e:
                print(e)
    
    if args.lfi:
        if not args.url:
            colors.error('Please enter an URL  for scanning')
            LOGGER.error('[-] Please enter an URL for scanning')
            sys.exit(1)
        try:
            colors.info('Initiating LFI Scan')

            from lib.website_scanner.lfi import lfiEngine
            print(dir(lfiEngine))
            lfiscanObj = lfiEngine.LFI(url=args.url, payload_path=os.getcwd()+'/payloads/lfi_payloads.json')
            lfiscanObj.startScanner()

        except ImportError:
            colors.error('Could not import the required module.')
            LOGGER.error('[-] Could not import the required module.')
            sys.exit(1)
        except Exception as e:
            LOGGER.error(e)
             