# -*- coding: utf-8; -*-
import argparse

from customs       import Agent
from customs.utils import logger, validate_path
from .cli_base     import CliBase

class AgentCommand(CliBase):
    """ Broker

    """
    def __init__(self, sub_parser):
        logger.setup_logging('cli')
        if not isinstance(sub_parser, argparse._SubParsersAction):
            raise TypeError(logger.error("parser should of an instance of argparse._SubParsersAction"))

        # Set up deploy parser and pass deploy function to defaults.
        self._parser = sub_parser.add_parser('agent')
        super(AgentCommand, self).__init__()
        self._build_arguments()
        self._parser.set_defaults(func=self.start)

    def _build_arguments(self):
        """
        build arguments for command.
        """
        self._parser.add_argument(
            '--docker-port',
            required=False,
            type=str,
            default='2375',
            help='port for docker daemon.'
        )

        self._parser.add_argument(
            '--docker-tls',
            required=False,
            type=validate_path,
            help='path to docker tls certs. example: /etc/docker/certs'
        )

        self._parser.add_argument(
            '--docker-verify',
            required=False,
            type=bool,
            default=True,
            help='validate docker tls certs. example: True or False'
        )

        self._parser.add_argument(
            '-r', '--reconcile',
            required=False,
            type=int,
            default=60,
            help='The amount of time between reconciliation in seconds. defaults to 60.'
        )

    def start(self, args, **extra_args):
        """Deploy a docker container to a specific container ship (host)

        :param args:
        :type args:
        """
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        docker_host = '{0}:{1}'.format(args.host, args.docker_port)
        agency_host = '{0}:{1}'.format(args.host, args.agency_port)

        customs = Agent(
            {'host': agency_host, 'tls_path': args.agency_tls, 'token': args.token, 'verify': args.agency_verify},
            args.reconcile,
            {'host': docker_host, 'tls_path': args.docker_tls, 'verify': args.docker_verify}
        )

        customs.start()

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)
