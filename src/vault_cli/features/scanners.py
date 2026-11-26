"""Scanner handlers."""

import os
import sys

from vault_cli import colors, errors


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
        errors.report_error('Could not import the required module.')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def ack(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
        errors.report_error('Could not import the required module.')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def fin(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
        errors.report_error('Could not import the required module')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)


def null(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
        errors.report_error('Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)


def xmas(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
        errors.report_error('Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)


def ping_sweep(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
            errors.report_error('Could not import the required module.')
        except Exception as e:
            errors.report_error(str(e), exc=e)


def arp_scan(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning')
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
            errors.report_error('Could not import the required module.')
        except Exception as e:
            errors.report_error(str(e), exc=e)


def ssl(args):
    if not args.url:
        errors.report_error('Please enter an URL for SSL scanning')
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
        errors.report_error('Could not import the required module.')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def os_scan(args):
    if args.url is None and args.ip is None:
        errors.report_error('Please provide either an IP address or an URL to '
                            'perform OS Scan')
        sys.exit(1)
    try:
        colors.info('OS Scan using Nmap')

        from lib.scanner.os_scan import os_scan

        os_scanObj = os_scan.OSScan(ip=args.ip, url=args.url)
        os_scanObj.os_scan()

    except ImportError:
        errors.report_error('Could not import the required module.')
    except Exception as e:
        errors.report_error(str(e), exc=e)
