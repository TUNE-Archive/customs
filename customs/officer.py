# -*- coding: utf-8; -*-
import asyncio
from multiprocessing import Process, Queue, Event
import os
import time

import json
import dateutil.parser
import docker
from docker.errors  import NotFound
from requests.utils import urlparse

from .event import DockerEvent
from .utils import logger, normalize_keys, ProcessHandler, validate_path


class Officer(Process):
    """ Agent officers enforce these laws for every person or thing that enters or leaves U.S. Among their many
    functions are detecting and confiscating contraband, making sure that import duties are paid, and preventing
    those without legal authorization from entering the United States.
    """
    API_VERSION = '1.20'
    TIMEOUT     = 60

    def __init__(self, docker_daemon:dict, dispatch_queue:Queue):
        self.url                = urlparse(docker_daemon.get('host'))
        self._client_session    = self.__configure_docker_client(docker_daemon)
        self._docker_info       = self._client_session.version()
        self._dispatch_queue    = dispatch_queue
        self._handler           = ProcessHandler()

        super(Officer, self).__init__()

    def start(self):
        self.daemon = True
        super(Officer, self).start()
        logger.info('Officer {0} reporting for duty.'.format(self.pid))

    def run(self):
        for event in self._client_session.events():
            try:
                results = normalize_keys(json.loads(event.decode('utf-8')))
            except Exception:
                logger.error('unable to deserialize event from docker event stream.')
                continue

            event = DockerEvent(
                docker_id=results.get('id'),
                image=results.get('from'),
                status=results.get('status'),
                epoch=results.get('time')
            )

            if event.type == 'container':
                logger.info('{0} adding event: {1} {2}: {3} to dispatch queue.'.format(
                    self.name,
                    event.status, event.type,
                    event.docker_id
                ))

                self._dispatch_queue.put(event)
            else:
                logger.info('{0} - customs currently only supports container events.'.format(self.name))

    def terminate(self):
        logger.info('Officer {0} standing down.'.format(self.pid))
        self._client_session.close()
        super(Officer, self).terminate()

    def __configure_docker_client(self, docker_daemon:dict) -> docker.Client:
        if self.url.scheme == 'https':
            for cert_name_type in ('ca', 'cert', 'key'):
                if 'tls_path' in docker_daemon and docker_daemon['tls_path']:
                    cert_path = validate_path(os.path.join(docker_daemon['tls_path'], "{0}.pem".format(cert_name_type)))
                else:
                    cert_path = None

                setattr(self, 'SSL_{0}_PATH'.format(cert_name_type.upper()), cert_path)

            if 'verify' in docker_daemon and isinstance(docker_daemon['verify'], bool):
                self.SSL_VERIFY = docker_daemon['verify']
            else:
                self.SSL_VERIFY = True

            if not self.SSL_VERIFY:
                self.SSL_CA_PATH = None

            tls_config = docker.tls.TLSConfig(
                client_cert=(self.SSL_CERT_PATH, self.SSL_KEY_PATH),
                ca_cert=self.SSL_CA_PATH,
                verify=self.SSL_VERIFY
            )

            return docker.Client(self.url.geturl(), tls=tls_config, timeout=self.TIMEOUT, version=self.API_VERSION)
        else:
            return docker.Client(self.url.geturl(), timeout=self.TIMEOUT, version=self.API_VERSION)


class Inspector(Process):
    API_VERSION = '1.20'
    TIMEOUT     = 60

    def __init__(self, docker_daemon:dict, brokerage_queue:Queue, dispatch_queue:Queue, inventory, inventory_event:Event):
        self.url              = urlparse(docker_daemon.get('host'))
        self._client_session  = self.__configure_docker_client(docker_daemon)
        self._docker_info     = self._client_session.version()
        self._brokerage_queue = brokerage_queue
        self._dispatch_queue  = dispatch_queue
        self._handler         = ProcessHandler()
        self._inventory_event = inventory_event
        self._inventory       = inventory
        self._start_time      = int(time.time())

        super(Inspector, self).__init__()

    def __configure_docker_client(self, docker_daemon:dict) -> docker.Client:
        if self.url.scheme == 'https':
            for cert_name_type in ('ca', 'cert', 'key'):
                if 'tls_path' in docker_daemon and docker_daemon['tls_path']:
                    cert_path = validate_path(os.path.join(docker_daemon['tls_path'], "{0}.pem".format(cert_name_type)))
                else:
                    cert_path = None

                setattr(self, 'SSL_{0}_PATH'.format(cert_name_type.upper()), cert_path)

            if 'verify' in docker_daemon and isinstance(docker_daemon['verify'], bool):
                self.SSL_VERIFY = docker_daemon['verify']
            else:
                self.SSL_VERIFY = True

            if not self.SSL_VERIFY:
                self.SSL_CA_PATH = None

            tls_config = docker.tls.TLSConfig(
                client_cert=(self.SSL_CERT_PATH, self.SSL_KEY_PATH),
                ca_cert=self.SSL_CA_PATH,
                verify=self.SSL_VERIFY
            )

            return docker.Client(self.url.geturl(), tls=tls_config, timeout=self.TIMEOUT, version=self.API_VERSION)
        else:
            return docker.Client(self.url.geturl(), timeout=self.TIMEOUT, version=self.API_VERSION)


    def start(self):
        self.daemon = True
        super(Inspector, self).start()
        logger.info('Inspector {0} reporting for duty.'.format(self.pid))

    def run(self):
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        loop = asyncio.get_event_loop()

        self._inventory_event.set()
        asyncio.ensure_future(self._take_inventory())
        asyncio.ensure_future(self._get_dispatch_instructions())

        try:
            loop.run_forever()
        finally:
            loop.close()

    def terminate(self):
        logger.info('Inspector {0} standing down.'.format(self.pid))
        self._client_session.close()

        super(Inspector, self).terminate()

    async def _get_dispatch_instructions(self, instructions:dict={}):
        try:
            if self._dispatch_queue.empty() or self._inventory_event.is_set():
                await asyncio.sleep(1)
            else:
                event = self._dispatch_queue.get()
                if isinstance(event, DockerEvent):
                    if event.docker_id in instructions:
                        event.meta_data = self._inventory[event.docker_id]

                        if event.meta_data:
                            event.name = event.meta_data.get('name').strip('/')
                            instructions[event.docker_id].append(event)
                        else:
                            logger.warning('unable to find container: {} metadata.'.format(event.docker_id))

                    else:
                        if event.docker_id not in self._inventory:
                            self._inventory_event.set()

                            while self._inventory_event.is_set():
                                await asyncio.sleep(1)

                        if event.docker_id in self._inventory:
                            event.meta_data = self._inventory[event.docker_id]

                            if event.meta_data:
                                event.name = event.meta_data.get('name').strip('/')
                                instructions[event.docker_id] = [event]
                            else:
                                logger.warning('unable to find container: {} metadata.'.format(event.docker_id))

                        else:
                            logger.warning('unable find container {0}.'.format(event.docker_id))
                else:
                    logger.error("an event that wasn't an instance of DockerEvent was passed to the dispatch queue.")

            if instructions:
                await self._final_inspection(instructions)

            asyncio.ensure_future(self._get_dispatch_instructions(instructions))

        except Exception as e:
            logger.error('inside get_dispatch instructions')
            logger.error(e)

    async def _take_inventory(self):
        if self._inventory_event.is_set():
            logger.info('{0} - {1}: taking inventory.'.format(self.name, self.pid))
            containers = self._client_session.containers(all=True)

            await self._add_inventory(containers)
            await self._remove_inventory(containers)

            logger.info('{0} - {1}: inventory complete.'.format(self.name, self.pid))
            self._inventory_event.clear()
        else:
            await asyncio.sleep(1)

        asyncio.ensure_future(self._take_inventory())

    async def _remove_inventory(self, containers):

        for docker_id in list(self._inventory.keys()):
            remove_item = True

            for container in containers:
                container = normalize_keys(container)
                if docker_id == container.get('id'):
                    remove_item = False

            if remove_item:

                del self._inventory[docker_id]

    async def _add_inventory(self, containers):
        try:
            tasks = []

            for container in containers:
                if isinstance(container, dict):
                    container = normalize_keys(container)
                    tasks.append(asyncio.ensure_future(self._inspect_container(container.get('id'))))
                else:
                    logger.error('The docker daemon returned an unexpected result: {}'.format(container))

            for result in asyncio.as_completed(tasks):
                container = await result

                if container is not None:
                    self._inventory[container.get('id')] = container

        except Exception as e:
            logger.error('error while adding inventory.')
            logger.error(e)

    async def _final_inspection(self, instructions:dict):
        """
        :param instructions:
        :return:
        """
        try:
            if instructions:
                docker_system_time         = normalize_keys(self._client_session.info()).get('system_time')
                docker_system_time_seconds = int(time.mktime(dateutil.parser.parse(docker_system_time, ignoretz=True).timetuple()))

                for docker_id in list(instructions.keys()):
                    events = instructions[docker_id]

                    validated = True
                    for event in events:

                        if abs(event.epoch - docker_system_time_seconds) < 10:
                            validated = False
                            break

                    if validated:
                        await self._update_brokerage_queue(events)
                        del instructions[docker_id]

        except Exception as e:
            logger.error('inside final inspection instructions')
            logger.error(e)

    async def _update_brokerage_queue(self, events):
        try:
            relevant_event = None

            for event in events:
                if event.status == 'destroy':
                    relevant_event = event
                    break
                elif event.status == 'create' and not relevant_event:
                    relevant_event = event
                elif event.status in ('restart', 'start'):
                    relevant_event = event

            if relevant_event is not None:
                logger.info(
                    '{0} adding event: {1} {2}: {3} to brokerage queue.'.format(
                        self.name,
                        relevant_event.status,
                        relevant_event.type,
                        relevant_event.docker_id
                    )
                )

                self._brokerage_queue.put(relevant_event)
        except Exception as e:
            logger.error(e)

    async def _inspect_container(self, id:str, retry_count:int=0):
        meta_data = None

        try:
            meta_data = normalize_keys(self._client_session.inspect_container(id))
        except NotFound:
            logger.error('unable to find container: {0} attempting to retry.'.format(id))
            retry_count += 1
            if retry_count < 3:
                meta_data = await self._inspect_container(id, retry_count)

        except Exception as e:
            logger.error('while trying to inspect container: {} error: {}'.format(id, e))

            pass

        return meta_data

    async def _inspect_image(self, id:str, retry_count:int=0):
        meta_data = None

        try:
            meta_data = normalize_keys(self._client_session.inspect_image(id))
        except NotFound:
            retry_count += 1
            if retry_count < 3:
                meta_data = await self._inspect_image(id, retry_count)
            else:
                return None

        return meta_data
