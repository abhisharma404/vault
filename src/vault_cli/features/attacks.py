"""Attack handlers."""

import sys

from vault_cli import colors, errors


def ddos(args):
    if args.url is None and args.ip is None:
        errors.report_error('Please provide either an IP address or an URL to '
                            'perform DDoS attack',
                            hint='Provide -u <url> or -ip <ip>.')
        sys.exit(1)
    else:
        if not args.port or not args.interval:
            colors.warning('Using default ports/interval for DDoS.')
        try:
            from lib.attacks.ddos import ddos

            ddosObj = ddos.DDoS(url=args.url, ip=args.ip,
                                start_port=args.start_port,
                                end_port=args.end_port, dport=args.port,
                                threads=args.threads, interval=args.interval)
            ddosObj.startAttack()
        except ImportError:
            errors.report_error('Could not import the required module',
                            code='E6001')
        except Exception as e:
            errors.report_error(str(e), exc=e)
            sys.exit(1)


def mac_flood(args):
    try:
        from lib.attacks.mac_flood import mac_flood

        mac_floodObj = mac_flood.MACFlood(interface=args.interface)
        mac_floodObj.startAttack()
    except ImportError:
        errors.report_error('Could not import the required module',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)
        sys.exit(1)


def arp_spoof(args):
    try:
        from lib.attacks.arp_spoof import arp_spoofer

        arpSpoofObj = arp_spoofer.ARPSpoof(ip=args.ip)
        arpSpoofObj.startSpoof()
    except ImportError:
        errors.report_error('Could not import the required module',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)


def ping_death(args):
    try:
        from lib.attacks.ping_death import ping_death

        ping_deathObj = ping_death.pingDeath(ip=args.ip, url=args.url)
        ping_deathObj.startAttack()
    except ImportError:
        errors.report_error('Could not import the required module',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)
        sys.exit(1)


def deauth(args):
    try:
        from lib.attacks.deauth import deauth_attack

        deauthObj = deauth_attack.Deauth(interface=args.interface,
                                         target_bssid=args.target_bssid)
        deauthObj.startProcess()
    except ImportError:
        errors.report_error('Could not import the required module',
                            code='E6001')
    except Exception as e:
        errors.report_error(str(e), exc=e)
        sys.exit(1)
