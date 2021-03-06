import argparse
import json
import logging

from enum import Enum

import pcomfortcloud

def print_result(obj, indent = 0):
    for key in obj:
        value = obj[key]

        if isinstance(value, dict):
            print(" "*indent + key)
            print_result(value, indent + 4)
        elif isinstance(value, Enum):
            print(" "*indent + "{0: <{width}}: {1}".format(key, value.name, width=25-indent))
        elif isinstance(value, list):
            print(" "*indent + "{0: <{width}}:".format(key, width=25-indent))
            for elt in value:
                print_result(elt, indent + 4)
                print("")
        else:
            print(" "*indent + "{0: <{width}}: {1}".format(key, value, width=25-indent))

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def namesFromEnum(enumCls):
	return list(map(lambda i: i.name, enumCls))

def main():
    """ Start pcomfortcloud Comfort Cloud command line """

    parser = argparse.ArgumentParser(
        description='Read or change status of pcomfortcloud Climate devices')

    parser.add_argument(
        'username',
        help='Username for pcomfortcloud Comfort Cloud')

    parser.add_argument(
        'password',
        help='Password for pcomfortcloud Comfort Cloud')

    parser.add_argument(
        '-t', '--token',
        metavar='FILE',
        help='File to store session cache in (default: %(default)s)',
        default='~/.pcomfortcloud-token.js')

    parser.add_argument(
        '-s', '--skipVerify',
        help='Skip Ssl verification if set as True',
        type=str2bool, nargs='?', const=True,
        default=False)

    parser.add_argument(
        '-r', '--raw',
        help='Raw dump of response',
        action='store_true',
        default=False)

    parser.add_argument(
        '-v', '--verbose', dest='verbosity',
        help='Increase verbosity of debug output',
        action='count',
        default=0)

    parser.add_argument(
        '-c', '--cache',
        help="Cached information is retrieved from the token file to speed up operation, (default: %(default)s)",
        type=pcomfortcloud.constants.Cache,
        choices=list(pcomfortcloud.constants.Cache),
        default=pcomfortcloud.constants.Cache.Token
    )

    commandparser = parser.add_subparsers(
        help='commands',
        dest='command')

    commandparser.add_parser(
        'list',
        help="Get a list of all devices")

    get_parser = commandparser.add_parser(
        'get',
        help="Get status of a device")

    get_parser.add_argument(
        dest='device',
        type=int,
        help='Device number #')

    set_parser = commandparser.add_parser(
        'set',
        help="Set status of a device")

    set_parser.add_argument(
        dest='device',
        type=int,
        help='Device number #'
    )

    set_parser.add_argument(
        '-p', '--power',
        choices=namesFromEnum(pcomfortcloud.constants.Power),
        help='Power mode')

    set_parser.add_argument(
        '-t', '--temperature',
        type=float,
        help="Temperature")

    set_parser.add_argument(
        '-f', '--fanSpeed',
        choices=namesFromEnum(pcomfortcloud.constants.FanSpeed),
        help='Fan speed')

    set_parser.add_argument(
        '-m', '--mode',
        choices=namesFromEnum(pcomfortcloud.constants.OperationMode),
        help='Operation mode')

    set_parser.add_argument(
        '-e', '--eco',
        choices=namesFromEnum(pcomfortcloud.constants.EcoMode),
        help='Eco mode')

    set_parser.add_argument(
        '-n', '--nanoe',
        choices=namesFromEnum(pcomfortcloud.constants.NanoeMode),
        help='Nanoe mode')

    # set_parser.add_argument(
    #     '--airswingauto',
    #     choices=[
    #         pcomfortcloud.constants.AirSwingAutoMode.Disabled.name,
    #         pcomfortcloud.constants.AirSwingAutoMode.AirSwingLR.name,
    #         pcomfortcloud.constants.AirSwingAutoMode.AirSwingUD.name,
    #         pcomfortcloud.constants.AirSwingAutoMode.Both.name],
    #     help='Automation of air swing')

    set_parser.add_argument(
        '-y', '--airSwingVertical',
        choices=namesFromEnum(pcomfortcloud.constants.AirSwingUD),
        help='Vertical position of the air swing')

    set_parser.add_argument(
        '-x', '--airSwingHorizontal',
        choices=namesFromEnum(pcomfortcloud.constants.AirSwingLR),
        help='Horizontal position of the air swing')

    dump_parser = commandparser.add_parser(
        'dump',
        help="Dump data of a device")

    dump_parser.add_argument(
        dest='device',
        type=int,
        help='Device number 1-x')

    history_parser = commandparser.add_parser(
        'history',
        help="Dump history of a device")

    history_parser.add_argument(
        dest='device',
        type=int,
        help='Device number 1-x')

    history_parser.add_argument(
        dest='mode',
        type=str,
        help='mode (Day, Week, Month, Year)')

    history_parser.add_argument(
        dest='date',
        type=str,
        help='date of day like 20190807')

    args = parser.parse_args()

    if args.verbosity > 1:
        level = logging.DEBUG
    elif args.verbosity > 0:
        level = logging.INFO
    else:
        level = logging.WARN
    logging.basicConfig(level=level, format='--- [%(levelname)s] %(message)s')

    session = pcomfortcloud.Session(args.username, args.password, args.token, args.raw, not args.skipVerify,
                                    caching=args.cache)
    session.login()
    try:
        if args.command == 'list':
            print("list of devices and its device id (1-x)")
            for idx, device in enumerate(session.get_devices()):
                if idx > 0:
                    print('')

                print("device #{}".format(idx + 1))
                print_result(device, 4)

        if args.command == 'get':
            if int(args.device) <= 0 or int(args.device) > len(session.get_devices()):
                raise Exception("device not found, acceptable device id is from {} to {}".format(1, len(session.get_devices())))

            device = session.get_devices()[int(args.device) - 1]
            print("reading from device '{}' ({})".format(device['name'], device['id']))

            print_result(session.get_device(device['id']))

        if args.command == 'set':
            if int(args.device) <= 0 or int(args.device) > len(session.get_devices()):
                raise Exception("device not found, acceptable device id is from {} to {}".format(1, len(session.get_devices())))

            device = session.get_devices()[int(args.device) - 1]
            print("writing to device '{}' ({})".format(device['name'], device['id']))

            kwargs = {}

            if args.power is not None:
                kwargs['power'] = pcomfortcloud.constants.Power[args.power]

            if args.temperature is not None:
                kwargs['temperature'] = args.temperature

            if args.fanSpeed is not None:
                kwargs['fanSpeed'] = pcomfortcloud.constants.FanSpeed[args.fanSpeed]

            if args.mode is not None:
                kwargs['mode'] = pcomfortcloud.constants.OperationMode[args.mode]

            if args.eco is not None:
                kwargs['eco'] = pcomfortcloud.constants.EcoMode[args.eco]

            if args.nanoe is not None:
                kwargs['nanoe'] = pcomfortcloud.constants.NanoeMode[args.nanoe]

            if args.airSwingHorizontal is not None:
                kwargs['airSwingHorizontal'] = pcomfortcloud.constants.AirSwingLR[args.airSwingHorizontal]

            if args.airSwingVertical is not None:
                kwargs['airSwingVertical'] = pcomfortcloud.constants.AirSwingUD[args.airSwingVertical]

            session.set_device(device['id'], **kwargs)

        if args.command == 'dump':
            if int(args.device) <= 0 or int(args.device) > len(session.get_devices()):
                raise Exception("device not found, acceptable device id is from {} to {}".format(1, len(session.get_devices())))

            device = session.get_devices()[int(args.device) - 1]

            print_result(session.dump(device['id']))

        if args.command == 'history':
            if int(args.device) <= 0 or int(args.device) > len(session.get_devices()):
                raise Exception("device not found, acceptable device id is from {} to {}".format(1, len(session.get_devices())))

            device = session.get_devices()[int(args.device) - 1]

            print_result(session.history(device['id'], args.mode, args.date))

    except pcomfortcloud.ResponseError as ex:
        print(ex.text)


# pylint: disable=C0103
if __name__ == "__main__":
    main()
