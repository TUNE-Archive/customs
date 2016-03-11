# -*- coding: utf-8; -*-
from customs.utils import validate_path


class CliBase(object):
    """Simple class to add some common arguments to to each command.
    """
    def __init__(self):
        """
        """
        if not hasattr(self, '_parser'):
            raise AttributeError("self._parser must be defined.")

        # TODO: needs to be updated.
        self._parser.add_argument(
            'host',
            type=str,
            default='127.0.0.1',
            metavar='Customs host url. default: 127.0.0.1',
            help="The host customs will be using to interact with."
        )

        self._parser.add_argument(
            '--token',
            type=str,
            required=False,
            help="Agency ACL token."
        )

        self._parser.add_argument(
            '--agency-tls',
            required=False,
            type=validate_path,
            help='path to agency tls certs. example: /etc/consul/certs'
        )

        self._parser.add_argument(
            '--agency-port',
            required=False,
            type=str,
            default='8500',
            help='port for agency'
        )

        self._parser.add_argument(
            '--agency-verify',
            required=False,
            type=bool,
            default=True,
            help='validate agency tls certs. example: True or False'
        )
