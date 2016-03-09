# -*- coding: utf-8; -*-
import asyncio
import re
from multiprocessing import Queue, Process, Event

from .agency import Agency
from .utils  import logger, ProcessHandler, normalize_keys


class Broker(Process):
    """ Agent broking or customs brokerage is a profession that involves the "clearing" of goods through customs
    barriers for importers and exporters (usually businesses). This involves the preparation of documents and/or
    electronic submissions, the calculation and payment of taxes, duties and excises, and facilitating communication
    between government authorities and importers and exporters.
    """
    def __init__(self, agency: Agency, brokerage_queue: Queue, inventory, inventory_event: Event, reconcile_event: Event):
        # TODO: must move the instantiation of agency into this class
        self._agency               = agency
        self._brokerage_queue      = brokerage_queue
        self._inventory            = inventory
        self._inventory_event      = inventory_event
        self._reconciliation_event = reconcile_event
        self._handler              = ProcessHandler()
        self._brokerage_clear_event = Event()

        super(Broker, self).__init__()

    def run(self):
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        loop = asyncio.get_event_loop()

        asyncio.ensure_future(self._reconcile())
        asyncio.ensure_future(self._start_clearing_brokerage_queue())

        try:
            loop.run_forever()
        finally:
            loop.close()

    def start(self):
        self.daemon = True
        super(Broker, self).start()

        # log some helpful info
        logger.info('Broker {0} reporting for duty.'.format(self.pid))
        logger.info('Agency: {0}'.format(self._agency.type))
        logger.info('Name: {0}'.format(self._agency.name))
        logger.info('Host: {0}'.format(self._agency.host))
        logger.info('Port: {0}'.format(self._agency.host_port))
        logger.info('Scheme: {0}'.format(self._agency.host_scheme))
        logger.info('Data Center: {0}'.format(self._agency.data_center))

    def terminate(self):
        logger.info('Broker {0} standing down.'.format(self.pid))
        super(Broker, self).terminate()

    async def _reconcile(self):
        if self._reconciliation_event.is_set() and not self._inventory_event.is_set() and not self._brokerage_clear_event.is_set():
            logger.info('{0}: stating reconciliation.'.format(self.name))
            current_services = normalize_keys(self._agency.services)
            tasks            = []
            active_services  = []

            for container_metadata in self._inventory.values():
                container_name         = container_metadata.get('name').strip('/')
                rule                   = await self.__find_rule(container_name)
                service_name           = self.__get_service_name(container_name, rule)
                active_services.append(service_name)

                tasks.append(
                    asyncio.ensure_future(
                        self.__process_cleared_goods(container_name, service_name, container_metadata, rule)
                    )
                )

            for service_name, service_metadata in current_services.items():
                if 'customs' in service_metadata.get('tags', []) and service_name not in active_services:
                    tasks.append(asyncio.ensure_future(self.__process_rejected_goods(service_name)))

            await asyncio.wait(tasks)
            logger.info('{0} - reconciliation complete.'.format(self.name))
            self._reconciliation_event.clear()
        else:
            await asyncio.sleep(1)

        asyncio.ensure_future(self._reconcile())

    async def _start_clearing_brokerage_queue(self):
        # TODO: add meta_data to event so we dont have to get it from the inventory.
        tasks = []
        try:
            if self._reconciliation_event.is_set() or self._brokerage_queue.empty():
                await asyncio.sleep(1)
            else:
                self._brokerage_clear_event.set()

                while not self._brokerage_queue.empty():
                    event = self._brokerage_queue.get()

                    if event:
                        logger.info(
                            '{0} - processing brokerage queue container: {1} status: {2}.'.format(
                                self.name,
                                event.docker_id,
                                event.status
                            )
                        )

                        rule         = await self.__find_rule(event.name)
                        service_name = self.__get_service_name(event.name, rule)

                        if event.status in ('create', 'start', 'restart'):
                            tasks.append(
                                asyncio.ensure_future(
                                    self.__process_cleared_goods(event.name, service_name, event.meta_data, rule)
                                )
                            )
                        elif event.status == 'destroy':
                            tasks.append(
                                asyncio.ensure_future(self.__process_rejected_goods(service_name))
                            )
                    else:
                        break

                if tasks:
                    await asyncio.wait(tasks)
                    self._inventory_event.set()

                self._brokerage_clear_event.clear()

        except Exception as e:
            logger.error('brockerage queue.')
            logger.error(e)

        asyncio.ensure_future(self._start_clearing_brokerage_queue())

    async def __process_cleared_goods(self, container_name: str, service_name: str, container_metadata: dict, rule):
        try:
            # TODO: validation
            service_checksum = self._agency.checksums.get(service_name)
            rule_checksum    = rule.md5sum()
            current_matadata = self._agency.service_metadata(service_name)

            if service_checksum and service_checksum == rule_checksum and current_matadata.get('id') == container_metadata.get('id'):
                pass
            else:
                checks, metadata, tags = await self.__apply_rules(container_metadata, rule)
                logger.info('registering container: {0} as service: {1}.'.format(container_name, service_name))

                network_mode  = container_metadata['host_config'].get('network_mode')
                exposed_ports = await self.__get_exposed_ports(container_metadata, network_mode)

                if network_mode == 'host':
                    ip_address = self._agency.config.get('advertise_addr')
                else:
                    ip_address = container_metadata['network_settings'].get('ip_address')

                if exposed_ports and ip_address:
                    exposed_port = exposed_ports.pop() if len(exposed_ports) == 1 else -1
                else:
                    exposed_port = None

                self._agency.register_service(
                    service_name,
                    rule_checksum,
                    check=checks.get('check'),
                    httpcheck=checks.get('httpcheck'),
                    interval=checks.get('interval'),
                    ttl=checks.get('ttl'),
                    address=ip_address if ip_address else None,
                    port=exposed_port,
                    tags=tags
                )

                self._agency.kv['{0}/{1}/{2}'.format(self._agency.name, 'containers', service_name)] = metadata
        except Exception as e:
            logger.error('process cleared goods. some kind of error.')
            logger.error(container_name)
            logger.error(service_name)

            logger.error(e)

    async def __get_exposed_ports(self, container_metadata: dict, network_mode: str):
        """
        expected value: {'80/tcp': [{'host_port': '8888', 'host_ip': '0.0.0.0'}], '443/tcp': None}
        """
        bound_ports = []

        if network_mode == 'host':
            exposed_ports = container_metadata['config'].get('exposed_ports', {})
            for exposed_port in exposed_ports.keys():
                port, protocol = exposed_port.split('/')

                bound_ports.append(int(port))
        else:
            exposed_ports = container_metadata['network_settings'].get('ports', {})

            for exposed_port in exposed_ports.values():
                if exposed_port:
                    for host_data in exposed_port:
                        for key, value in host_data.items():
                            if key == 'host_port':
                                bound_ports.append(int(value))

        return bound_ports

    async def __process_rejected_goods(self, service_name):
        try:
            logger.info('{0} - deregistering service: {1}.'.format(self.name, service_name))
            self._agency.deregister_service(service_name)
        except Exception as e:
            logger.error('process rejected goods')
            logger.error(e)

    async def __apply_rules(self, container_metadata, rule):
        tags     = await self.__apply_tag_rules(rule, container_metadata)
        metadata = await self.__apply_metadata_rules(rule.metadata, container_metadata)
        checks   = await self.__apply_check_rules(rule)

        return checks, metadata, tags

    async def __find_rule(self, container_name):
        rules = []
        for rule_name in self._agency.rules:
            if rule_name == 'default':
                continue

            rule = self._agency.get_rule(rule_name)
            if rule.service_regex is not None:
                regex = re.compile(r'{0}'.format(rule.service_regex), flags=re.IGNORECASE)
            else:
                regex = re.compile(r'{0}'.format(rule_name), flags=re.IGNORECASE)

            if regex.match(container_name):
                logger.info('found service match within rule {0}.'.format(rule_name))
                rules.append(rule)

        if len(rules) == 1:
            return rules.pop()

        elif len(rules) > 1:
            logger.error(
                'Found multiple regex matches using default rule. To fix the issue please update you rule '
                'service_regex in services: {0}'.format(', '.join([rule.name for rule in rules]))
            )
            return self._agency.get_rule('default')

        else:
            logger.info('Was unable to find a rule with a matching service regex using default.')
            return self._agency.get_rule('default')

    async def __apply_check_rules(self, rule):
        # TODO: consider allowing folks to add their own checks outside of what consulate provides.
        # TODO: validate the checks. ie check or http
        return rule.checks

    async def __apply_metadata_rules(self, metadata_rules, container_metadata, metadata=None, ancestors=None) -> dict:
        try:
            metadata  = {} if metadata  is None else metadata
            ancestors = [] if ancestors is None else ancestors

            if metadata_rules:
                for key, value in metadata_rules.items():

                    if isinstance(value, dict):
                        ancestors.append(key)
                        await self.__apply_metadata_rules(value, container_metadata, metadata, ancestors)
                        ancestors.clear()

                    elif isinstance(value, bool) and value is True:
                        if ancestors:
                            current_metadata = metadata

                            for ancestor in ancestors:
                                current_container_metadata = container_metadata.get(ancestor)

                                if current_container_metadata is None:
                                    logger.error('unable to find {0} in {1} -> {2}.'.format(ancestor, ' -> '.join(ancestors), key))
                                    continue

                                if ancestor not in current_metadata:
                                    current_metadata[ancestor] = {}

                                current_metadata = metadata[ancestor]

                            if key in current_container_metadata:
                                current_metadata[key] = current_container_metadata[key]
                            else:
                                logger.error(
                                    'Was unable to find "{0} -> {1}" in container inspect response. This is probably due to '
                                    'docker response object changes during releases.  If you want them to stop please remove '
                                    'them from your rules or update docker.'.format(' -> '.join(ancestors), key)
                                )
                        else:
                            value = container_metadata.get(key)
                            metadata[key] = value

                    else:
                        logger.error('Rules values must be a boolean or a dict. Please update your rules.')
        except Exception as e:
            logger.error(e)

        return metadata

    async def __apply_tag_rules(self, rule, container_metadata) -> list:
        tags = ['customs']

        try:
            if rule.tags:
                for tag_rule in rule.tags:
                    if 'inspect' in tag_rule:
                        if '=' in tag_rule:
                            lookup_key, look_value_key = tag_rule.split('=')
                            tag  = None

                            if '.' in lookup_key:
                                for key in lookup_key.split('.'):
                                    if key == 'inspect':
                                        continue

                                    if tag is None:
                                        tag = container_metadata.get(key)
                                    else:
                                        tag = tag.get(key)

                                tag = None if tag is None else tag.get(look_value_key)

                            else:
                                tag = container_metadata.get(look_value_key)

                            if tag is None:
                                logger.error('unable to find {0} in container inspect response.'.format(tag_rule))
                            else:
                                tags.append(tag)
                        else:
                            logger.error(
                                'When adding "inspect" tags to customs rules they must be in one of the follow formats: '
                                'inspect=key or inspect.key=key'
                            )
                    else:
                        tags.append(tag_rule)
        except Exception as e:
            logger.error(e)

        return tags

    def __get_service_name(self, container_name: str, rule) -> str:
        regex = re.compile(r'{0}'.format(rule.service_regex), flags=re.IGNORECASE)
        match = regex.search(container_name)

        if match:
            return match.group(0)
        else:
            return container_name
