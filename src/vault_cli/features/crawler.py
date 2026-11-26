"""Crawler handlers."""

import sys

from vault_cli import colors, errors


def crawl(args):
    if args.url is None:
        errors.report_error('Please provide either an URL to perform Crawling')
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
        except ImportError:
            errors.report_error('Could not import the required module')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)


def scrap(args):
    if args.url is None:
        errors.report_error('Please provide URL to perform Scraping')
        sys.exit(1)
    else:
        try:
            from lib.crawler import finder
            links, path = crawl(args)
            finder.initiate(links, path)
            print('[X]Scraping completed')

        except ImportError:
            errors.report_error('Could not import the required module')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)
