# -*- coding: utf-8; -*-
import json
import os
from urllib.parse import urlparse

import consulate
import requests
import yaml
from consulate.adapters import Request as ConsulateRequest
from yaml               import YAMLError, SafeLoader

from .rules        import Rules
from .utils        import normalize_keys, logger


class Agency(object):
    """ Agency is a abstraction of the Consul
    """
    ROOT_FOLDER = '.customs'

    def __init__(self, **agency):

        url = urlparse(agency.get('host'))
        if not url.hostname:
            logger.warning('agency host: {0} did not include a scheme defaulting to http.'.format(agency.get('host')))
            url = urlparse('http://{0}'.format(agency.get('host')))

        self._data_center = None
        self._host        = url.hostname
        self._host_port   = url.port or 8500
        self._host_scheme = url.scheme
        self._token       = os.getenv('AGENCY_TOKEN', agency.get('token'))
        self._type        = 'consul'

        # set adapter tls constant.
        RequestAdapter.TLS = {'path': agency.get('tls_path'), 'verify': agency.get('verify')}

        # create client before setting data center. This allows us to validate existence of the data center.
        self.__create_consul_client()
        self.__set_local_agent_data()
        self._checksums = self.__load_checksums()

    @property
    def kv(self):
        """
        Return data store for agency.
        """
        return self._consul.kv

    @property
    def checks(self):
        checks = self._consul.agent.checks()
        if checks:
            return checks[0]

        return None

    @property
    def checksums(self) -> dict:
        return self._checksums

    @property
    def catalog(self):
        return self._consul.catalog

    @property
    def config(self):
        return self._config

    @property
    def data_center(self):
        return self._data_center

    @data_center.setter
    def data_center(self, value):
        self._data_center = value
        self.__create_consul_client()

    @property
    def host(self):
        return self._host

    @property
    def host_port(self):
        return self._host_port

    @property
    def host_scheme(self):
        return self._host_scheme

    @property
    def name(self):
        return self._name

    @property
    def rules(self):
        return [key.split('/')[1] for key in self.kv.find(self.ROOT_FOLDER).keys()]

    @property
    def type(self):
        return self._type

    @property
    def services(self):
        return self._consul.agent.services()[0]

    ##
    # public methods
    ##
    def create_rule(self, rule):
        if not isinstance(rule, Rules):
            raise TypeError("rule must be an instance of Rules")

        self.kv['{0}/{1}'.format(self.ROOT_FOLDER, rule.name)] = rule.to_yaml()

    def deregister_service(self, service_name):
        if self.checksums.get(service_name):
            del self.checksums[service_name]

            self.kv['{0}/containers/checksums'.format(self.name)] = yaml.safe_dump(
                self._checksums,
                default_flow_style=False
            ).encode('utf-8')
        else:
            logger.info('was unable to find check some for service: {}'.format(service_name))

        self._consul.agent.service.deregister(service_name)
        del self.kv['{}/{}/{}'.format(self.name, 'containers', service_name)]

    def get_rule(self, service: str):
        rules_data = self.kv.get('{0}/{1}'.format(self.ROOT_FOLDER, service))

        if rules_data:
            return Rules(service, rules_data)
        else:
            return None

    def register_service(self, service_name, rule_checksum, **kwargs):

        self._checksums[service_name] = rule_checksum
        self.kv['{0}/containers/checksums'.format(self.name)] = yaml.safe_dump(
            self._checksums,
            default_flow_style=False
        ).encode('utf-8')

        try:
            self._consul.agent.service.register(
                service_name,
                **kwargs
            )
        except ValueError as e:
            logger.error(e)

    def update_rule(self, rule):
        self.create_rule(rule)

    def service_metadata(self, service_name: str) -> dict:
        service_metadata = self.kv.get('{0}/containers/{1}'.format(self.name, service_name), {})

        if service_metadata:
            try:
                service_metadata = normalize_keys(json.loads(service_metadata))
            except Exception:
                logger.error('there is a syntax error in {} -> {} metadata.'.format(self.name, service_name))
        else:
            logger.info('was unable to find metadata for {} -> {}.'.format(self.name, service_name))

        return service_metadata

    ##
    # private methods
    ##
    def __create_consul_client(self):
        self._consul = consulate.Consul(
            adapter=RequestAdapter,
            host=self.host,
            port=self.host_port,
            datacenter=None,
            token=self._token,
            scheme=self.host_scheme
        )

        if self.data_center is None:
            pass

        elif self.data_center in self.catalog.datacenters():
            self._consul = consulate.Consul(
                adapter=RequestAdapter,
                host=self.host,
                port=self.host_port,
                datacenter=self.data_center,
                token=self._token,
                scheme=self.host_scheme
            )

        else:
            raise LookupError(
                'unable to find {0} in available data centers: {1}'.format(self.data_center, ', '.join(self.catalog.datacenters()))
            )

    def __set_local_agent_data(self):
        # a bit of a hack need to submit a pr to consulate.
        results          = normalize_keys(self._consul.agent._get_response_body(['self'], None))
        self._config     = results.get('config')
        self._member     = results.get('member')
        self._name       = self._member.get('name')
        self.data_center = self.config.get('datacenter')

    def __load_checksums(self):
        checksum_data = self.kv.get('{0}/containers/checksums'.format(self.name))

        try:
            if checksum_data:
                data = normalize_keys(SafeLoader(checksum_data).get_data(), snake_case=False)
            else:
                data = {}

            return data

        except YAMLError as e:
            if hasattr(e, 'problem_mark'):
                raise SyntaxError(
                    "There is a syntax error in the rules line: {0} column: {1}".format(
                        e.problem_mark.line,
                        e.problem_mark.column
                    )
                )
            else:
                raise SyntaxError("There is a syntax error in the rules.")


class RequestAdapter(ConsulateRequest):
    TLS = None

    def __init__(self, timeout=10):
        super(RequestAdapter, self).__init__(timeout)
        self.tls = self.TLS

        # set up certs.
        self.session        = requests.Session()
        self.session.cert   = (self.tls['cert_path'], self.tls['key_path']) if self.tls.get('cert_path') else None
        self.session.verify = self.tls['verify']

    @property
    def tls(self):
        return self._tls

    @tls.setter
    def tls(self, tls: dict):
        if not isinstance(tls, dict):
            raise TypeError('tls must be a dict.')

        self._tls = {
            "cert_path": None,
            "key_path": None,
            "ca_path": None,
            "verify": tls.get('verify', True)
        }

        path = tls.get('path')

        if path:
            if not os.path.exists(path):
                raise OSError("tls['path'] '{0}' don't exist".format(path))

            for file_name in ('key', 'cert', 'ca'):
                path_to_file = os.path.join(path, '{0}.pem'.format(file_name))

                if not os.path.isfile(path_to_file):
                    raise OSError("tls: was unable to find {0}.".format(path_to_file))

            self._tls["cert_path"] = os.path.join(path, 'cert.pem')
            self._tls["key_path"]  = os.path.join(path, 'key.pem')
            self._tls["verify"]    = os.path.join(path, 'ca.pem')
