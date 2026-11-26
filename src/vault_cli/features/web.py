"""Website scanner handlers (XSS, LFI)."""

import sys

from vault_cli import colors, errors, lib


def xss(args):
    if not args.url:
        errors.report_error('Please enter an URL for XSS Scanning')
        sys.exit(1)

    links = []

    if args.this:
        colors.success('Performing XSS Vulnerability Scan on : {}'
                       .format(args.url))
        links.append(args.url)
    else:
        colors.success('Collecting all the links, crawling : {}'
                       .format(args.url))
        try:
            from lib.website_scanner.xss.crawler import Crawl
            crawlObj = Crawl(url=args.url)
            links = crawlObj.getList()
        except ImportError:
            errors.report_error('Could not import the required module.')
        except Exception as e:
            errors.report_error(str(e), exc=e)

    try:
        from lib.website_scanner.xss import xss as xss_module

        xssScanObj = xss_module.XSS(url=links,
                                    payload_file=lib.payload_path(
                                        'xss_payloads.txt'))
        xssScanObj.initiateEngine()
    except ImportError:
        errors.report_error('Could not import the required module')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)


def lfi(args):
    if not args.url:
        errors.report_error('Please enter an URL for scanning')
        sys.exit(1)
    try:
        colors.info('Initiating LFI Scan')

        from lib.website_scanner.lfi import lfiEngine
        lfiscanObj = lfiEngine.LFI(url=args.url,
                                   payload_path=lib.payload_path(
                                       'lfi_payloads.json'))
        lfiscanObj.startScanner()

    except ImportError:
        errors.report_error('Could not import the required module.')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)
