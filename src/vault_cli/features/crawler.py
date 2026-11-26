"""Crawler handlers."""

import sys

from vault_cli import colors, errors


def crawl(args):
    if args.url is None:
        errors.report_error('Please provide either an URL to perform Crawling',
                            code='E1003', hint='Provide -u <url>.')
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
                links = C.start(return_set=True)
                if not links:
                    colors.warning('No links were collected.')
                return links
        except ImportError:
            errors.report_error('Could not import the required module',
                            code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)


def scrap(args):
    if args.url is None:
        errors.report_error('Please provide URL to perform Scraping',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    else:
        try:
            from lib.crawler import finder
            links, path = crawl(args)
            if not links:
                colors.warning('No links were collected.')
            finder.initiate(links, path)
            print('[X]Scraping completed')

        except ImportError:
            errors.report_error('Could not import the required module',
                            code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)
