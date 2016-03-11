# -*- coding: utf-8; -*-
import os
import time
from multiprocessing import Queue, Manager, Event

from .utils            import logger, ProcessHandler
from .agency           import Agency
from .broker           import Broker
from .officer          import Officer, Inspector


class Agent(object):

    def __init__(self, agency: dict, reconcile_tick: int, docker_daemon: dict={}):
        """
        :return:
        """
        self._agency          = Agency(**agency)
        self._brokerage_queue = Queue()
        self._dispatch_queue  = Queue()
        self._docker_daemon   = self.__get_docker_daemon_info(docker_daemon)
        self._handler         = ProcessHandler(exit_on_term=False)
        self._manager         = Manager()
        self._inventory       = self._manager.dict()
        self._take_inventory  = Event()
        self._reconcile       = Event()
        self._reconcile_tick  = reconcile_tick
        self._officer         = Officer(self._docker_daemon, self._dispatch_queue)

        self._inspector = Inspector(
            self._docker_daemon,
            self._brokerage_queue,
            self._dispatch_queue,
            self._inventory,
            self._take_inventory
        )

        self._broker = Broker(
            self._agency,
            self._brokerage_queue,
            self._inventory,
            self._take_inventory,
            self._reconcile
        )

    def start(self):
        logger.info('Agent {0} at your service.'.format(os.getpid()))
        self._officer.start()
        self._inspector.start()
        self._broker.start()

        try:
            counter = 0

            while True:
                if self._handler.received_term_signal:
                    print('here here here in side term signal')
                    break

                time.sleep(1)

                if counter % 5 is 0:
                    self._check_workers()

                if counter is self._reconcile_tick:
                    counter = 0

                    self._take_inventory.set()
                    self._reconcile.set()

                counter += 1

        finally:
            self.__kill_workers()

    def _check_workers(self):
        if not self._inspector.is_alive():
            self._inspector.terminate()
            self._inspector = Inspector(
                self._docker_daemon,
                self._brokerage_queue,
                self._dispatch_queue,
                self._inventory,
                self._take_inventory
            )

            self._inspector.start()

        if not self._officer.is_alive():
            self._officer.terminate()
            self._officer = Officer(self._docker_daemon, self._dispatch_queue)
            self._officer.start()

        if not self._broker.is_alive():
            self._broker.terminate()
            self._broker = Broker(
                self._agency,
                self._brokerage_queue,
                self._inventory,
                self._take_inventory,
                self._reconcile
            )

            self._broker.start()

    def __get_docker_daemon_info(self, docker_daemon: dict) -> dict:
        if not docker_daemon.get('host'):
            docker_daemon['host'] = os.getenv('DOCKER_HOST')

            if docker_daemon['host']:
                raise LookupError(
                    logger.error("Unable to find docker ENV var: DOCKER_HOST and docker host wasn't provided to the cli.")
                )

            path = os.getenv('DOCKER_CERT_PATH')
            if path:
                docker_daemon['tls_path'] = os.path.realpath(path)

            docker_daemon['verify'] = os.getenv('DOCKER_TLS_VERIFY')
            if docker_daemon['verify'] == 'yes':
                docker_daemon['verify'] = True
            elif docker_daemon['verify'] == 'no':
                docker_daemon['verify'] = False

        if 'tcp://' in docker_daemon['host']:
            if docker_daemon.get('tls_path'):
                docker_daemon['host'] = docker_daemon['host'].replace('tcp://', 'https://')
            else:
                docker_daemon['host'] = docker_daemon['host'].replace('tcp://', 'http://')

        return docker_daemon

    def __kill_workers(self):
        self._officer.terminate()
        self._broker.terminate()
        self._inspector.terminate()
