"""Miscellaneous / "others" handlers (info gathering, fuzzing, dorking, etc.)."""

import os
import sys

from vault_cli import colors, errors


def info(args):
    if not args.url:
        errors.report_error('Please enter an URL for information gathering',
                            code='E1003', hint='Provide -u <url>.')
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
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def comment(args):
    if not args.url:
        errors.report_error('Please enter an URL for finding comments',
                            code='E1003', hint='Provide -u <url>.')
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
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def email(args):
    if not args.url:
        errors.report_error('Please enter an URL for finding emails',
                            code='E1003', hint='Provide -u <url>.')
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
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def jquery(args):
    if not args.url:
        errors.report_error('Please enter an URL for jquery checking',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    try:
        from lib.others.info_gathering import jquery_check

        jquery_checkObj = jquery_check.JqueryCheck(url=args.url)
        jquery_checkObj.start_engine()

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e, code='E4001')


def fuzz(args):
    if not args.url:
        errors.report_error('Please enter an URL for fuzzing',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    try:
        from lib.others.fuzzer import fuzzer
        colors.info('Performing fuzzing on : {}'.format(args.url))
        fuzzObj = fuzzer.Fuzzer(base_url=args.url, thread_num=args.threads)
        fuzzObj.initiate()

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def dork(args):
    if args.dork:
        try:
            from lib.others.google_dork import dorker

            dorks = args.dork
            try:
                page = int(input("\nNumber of Pages to scrap :: \033[1;37m"))
            except ValueError:
                errors.report_error('Invalid page count', code='E1002',
                                    hint='Enter an integer page count.')
                sys.exit(2)

            print('\n\033[1;37m[>]Searching ...\033[1;37m  \n')
            try:
                web_lists = dorker.start_dorking(dorks, page)
            except Exception as e:
                errors.report_error(str(e), exc=e, code='E4001')
                return

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

        except ImportError:
            errors.report_error('Could not import the required module.',
                                code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e, code='E4001')


def whois(args):
    if not args.ip:
        errors.report_error('Please enter an IP for Whois lookup',
                            code='E1004', hint='Provide -ip <ip>.')
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
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e,
                            hint='The WHOIS service may be unreachable; check '
                                 'connectivity and retry.')


def admin_panel(args):
    if args.url is None:
        errors.report_error('Please provide either an URL for finding admin '
                            'panel', code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    else:
        try:
            from lib.others.admin_panel import admin_panel

            admin_panel.find_admin_panel(args.url)
        except ImportError:
            errors.report_error('Could not import the required module',
                            code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)


def bruteforce(args):
    if not args.url:
        errors.report_error('Please enter an URL for bruteforce',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    if not args.username:
        errors.report_error('A username is required for brute force',
                            code='E1010', hint='Provide -username <user>.')
        sys.exit(2)
    try:
        from lib.others.bruteforce_login import bruteforce_login
        colors.info('Performing bruteforce on : {}'.format(args.url))
        bruteforceObj = bruteforce_login.BruteforceLogin(url=args.url,
                                                         threads=args.threads,
                                                         user=args.username)
        bruteforceObj.startAttack()

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def detect_cms(args):
    if not args.url:
        errors.report_error('Please enter an URL for CMS detecting',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    try:
        from lib.others.detect_cms import detect_cms

        detect_cmsObj = detect_cms.DetectCMS(url=args.url)
        detect_cmsObj.start_engine()

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def open_redirect(args):
    if not args.url:
        errors.report_error('Please enter an URL for scanning',
                            code='E1003', hint='Provide -u <url>.')
        sys.exit(1)
    else:
        try:
            colors.info("Testing for open redirection Vulnerability")

            from lib.others.open_redirection import redirection
            redirection.ORVT(args.url)

        except ImportError:
            errors.report_error('Could not import the required module',
                            code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)


def detect_honeypot(args):
    if not args.ip:
        errors.report_error('Please enter an IP address for scanning',
                            code='E1004', hint='Provide -ip <ip>.')
        sys.exit(1)
    try:
        colors.info('Detecting honeypot: ')

        from lib.others.detect_honeypots import honeypots

        honeypots.honeypot(args.ip)

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e, code='E4001')
