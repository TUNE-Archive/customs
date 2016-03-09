# -*- coding: utf-8; -*-
import argparse

from .cli_base     import CliBase
from customs.utils import logger
from customs       import Agency, Rules


class RulesCommand(CliBase):
    """ Rules

    """
    def __init__(self, sub_parser):
        logger.setup_logging('cli')
        if not isinstance(sub_parser, argparse._SubParsersAction):
            raise TypeError(logger.error("parser should of an instance of argparse._SubParsersAction"))

        # Set up rules commands.
        self._parser = sub_parser.add_parser('rules')
        super(RulesCommand, self).__init__()
        self._parser.set_defaults(func=self.__default)
        self.__add_sub_commands()

    def __add_sub_commands(self):
        sub_parser = self._parser.add_subparsers(
            title='rules',
            description='command to interact with customs rules.',
            help='additional help'
        )

        # create rules parser
        create_parser = sub_parser.add_parser('create')
        create_parser.add_argument(
            'service',
            metavar='SERVICE_NAME',
            default='default',
            type=str,
            help='name of rule uou would like to create.'
        )
        create_parser.set_defaults(func=self.__create)

        # edit rules parser
        edit_parser = sub_parser.add_parser('edit')
        edit_parser.add_argument(
            'service',
            metavar='SERVICE_NAME',
            default='default',
            type=str,
            help='name of rule uou would like to edit.'
        )
        edit_parser.set_defaults(func=self.__edit)

    def __default(self, args, **extra_args):
        """ Rules
        """
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        agency_host = '{0}:{1}'.format(args.host, args.agency_port)
        agency = Agency(host=agency_host, token=args.token)
        if agency.rules:
            for rule in agency.rules:
                logger.info(rule)
        else:
            logger.error('There are no rules defined. Please create a default run the following command:'
                         '\"customs rules {0} create default\"'.format(agency_host))

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)

    def __create(self, args, **extra_args):
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        agency_host = '{0}:{1}'.format(args.host, args.agency_port)
        agency = Agency(host=agency_host, token=args.token)

        if args.service != 'default' and 'default' not in agency.rules:
            logger.warning('There is no default rules defined. Please fill out the default configuration file.')
            rule = Rules.create()
            agency.create_rule(rule)
            logger.warning('The default rule has been created if you still wish to create {0} please '
                           'rerun the command.'.format(args.service))

        elif args.service in agency.rules:
            logger.error('{0} has already been created. If you wish to edit the rules for {0} please run:'
                         ' customs rules {1} edit {0}'.format(args.service, agency.host))
        else:
            rule = Rules.create(args.service)
            agency.create_rule(rule)

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)

    def __edit(self, args, **extra_args):
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        agency_host = '{0}:{1}'.format(args.host, args.agency_port)
        agency = Agency(host=agency_host, token=args.token)

        if args.service in agency.rules:
            rule = agency.get_rule(args.service)
            rule.edit()
            agency.update_rule(rule)
        else:
            logger.error(
                'Was unable to find rules for service: {0}. Please run: '
                '\"customs rules {1} create {0}\"'.format(args.service, agency.host)
            )

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)

# logger.warning(
#     'A Service specific rules has not been defined for {0}. The customs default rule will be used. '
#     'To configure unique rules for {0} please run: \"customs rules {1} services '
#     '{0} create\"'.format(args.service, agency.host)
# )
