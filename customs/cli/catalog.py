# -*- coding: utf-8; -*-
import argparse

from customs       import Agency
from customs.utils import logger
from .cli_base     import CliBase


class CatalogCommand(CliBase):
    """ Catalog
    """
    def __init__(self, sub_parser):
        logger.setup_logging('cli')
        if not isinstance(sub_parser, argparse._SubParsersAction):
            raise TypeError(logger.error("parser should of an instance of argparse._SubParsersAction"))

        # Set up rules commands.
        self._parser = sub_parser.add_parser('catalog')
        super(CatalogCommand, self).__init__()
        self._add_sub_commands()

    def _add_sub_commands(self):
        sub_parser = self._parser.add_subparsers(
            title='catalog',
            description='command to search agency metadata.',
            help='additional help'
        )
        # add data-centers sub command.
        CatalogDataCenters(sub_parser)

        # add services sub command.
        CatalogServices(sub_parser)

class CatalogDataCenters(object):

    def __init__(self, sub_parser):
        if not isinstance(sub_parser, argparse._SubParsersAction):
            raise Exception("parser should of an instance of argparse.ArgumentParser")

        # Set up data-centers catalog sub command.
        self._parser = sub_parser.add_parser('data-centers')
        self._parser.set_defaults(func=self._list)

    def _list(self, args, **extra_args):
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        agency_host = '{0}:{1}'.format(args.host, args.agency_port)
        agency = Agency(host=agency_host, token=args.token)

        data_centers = agency.catalog.datacenters()
        if isinstance(data_centers, list):
            for data_center in agency.catalog.datacenters():
                logger.info(data_center)
        else:
            logger.info(data_centers)

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)

class CatalogServices(object):

    def __init__(self, sub_parser):
        if not isinstance(sub_parser, argparse._SubParsersAction):
            raise Exception("parser should of an instance of argparse.ArgumentParser")

        # Set up data-centers catalog sub command.
        self._parser = sub_parser.add_parser('services')
        self._parser.set_defaults(func=self._list)

    def _list(self, args, **extra_args):
        if not isinstance(args, argparse.Namespace):
            raise TypeError(logger.error("args should of an instance of argparse.Namespace"))

        agency_host = '{0}:{1}'.format(args.host, args.agency_port)
        agency = Agency(host=agency_host, token=args.token)

        for services in agency.catalog.services():
            if isinstance(services, dict):
                for service, tags in services.items():
                    logger.info(service)
            else:
                logger.info(services)

        exit_code = 0
        if exit_code != 0:
            exit(exit_code)
