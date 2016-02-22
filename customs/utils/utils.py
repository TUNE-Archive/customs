# -*- coding: utf-8; -*-
import asyncio
import functools
import json
import os
import re
import signal

from . import logger


def validate_uri(uri, scheme=True):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', flags=re.IGNORECASE)

    if regex.match(uri):
        return uri
    else:
        raise TypeError('%r is not a uri.' % uri)


def validate_path(path):
    if os.path.exists(path):
        return path
    else:
        raise SystemError("{0} doesn't exist.".format(path))


def generate_path(ssl_cert_path, path):
    if os.path.exists(os.path.join(ssl_cert_path, path)):
        return os.path.join(os.path.abspath(ssl_cert_path), path)


def is_valid_domain_name(domain_name):
    if len(domain_name) > 63:
        return False

    allowed = re.compile(r'[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*', re.IGNORECASE)
    return allowed.match(domain_name)


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False

    if hostname[-1] == ".":
        hostname = hostname[:-1]

    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def is_valid_ip(ip):
    regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', flags=re.IGNORECASE)

    return regex.match(ip)


# pre-compile regex
# there is a small bug in this where if you pass SomethingIs_Okay you will get two _ between is and okay
first_cap_re = re.compile('(.)([A-Z][a-z]+)')
all_cap_re = re.compile('([a-z0-9])([A-Z])')


def find_key(key, var):
    if hasattr(var, 'iteritems'):
        for k, v in var.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in find_key(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in find_key(key, d):
                        yield result


def normalize_keys(suspect, snake_case=True):
    """
    take a dict and turn all of its type string keys into snake_case
    """
    if not isinstance(suspect, dict):
        raise TypeError('you must pass a dict.')

    for key in list(suspect):
        if not isinstance(key, str):
            continue

        if snake_case:
            s1 = first_cap_re.sub(r'\1_\2', key)
            new_key = all_cap_re.sub(r'\1_\2', s1).lower()  # .replace('-', '_')
        else:
            new_key = key.lower()

        value = suspect.pop(key)
        if isinstance(value, dict):
            suspect[new_key] = normalize_keys(value, snake_case)

        elif isinstance(value, list):
            for i in range(0, len(value)):

                if isinstance(value[i], dict):
                    normalize_keys(value[i], snake_case)

            suspect[new_key] = value
        else:
            suspect[new_key] = value

    return suspect


def parse_hostname(uri):
    """
    This will parse the hostname and return it on match.  If no match is found it will raise a TypeError.
    :param uri:
    :return hostname:
    """""
    regex = re.compile(r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z]{2,}\.?)|'  # allow domain
                       r'localhost|'  # allow localhost
                       r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # allow ip
                       flags=re.IGNORECASE)

    match = regex.search(uri)

    if match:
        return match.group(0)
    else:
        raise TypeError("{0} doesn't contain a valid hostname.".format(uri))


def path_regex(path):
    """
    ^(\/{1}([a-zA-Z0-9\._-])*)(\/{1}([a-zA-Z0-9\._-])+)*(\/|([a-zA-Z0-9\._-])+)$
    """
    regex = re.compile(r'^((|\/{1})([a-zA-Z0-9\._-])*)(\/{1}([a-zA-Z0-9\._-])+)*(\/|([a-zA-Z0-9\._-])+)$')

    return regex.match(path)


def parse_http_scheme(uri):
    """
    match on http scheme if no match is found will assume http
    """
    regex = re.compile(
        r'^(?:http)s?',
        flags=re.IGNORECASE
    )
    match = regex.match(uri)

    return match.group(0)


def parse_port(uri):
    """
    match on port if provided within the
    """
    regex = re.compile(
        r'^.*:(?P<port>\d+)',
        flags=re.IGNORECASE
    )
    match = regex.match(uri)

    return match.group(1) if match else None


def parse_ssl_certificates(ssl_cert_path):
    """
    validate ssl_cert_path and build object from certificates in directory
    """
    # TODO - perform validation of ssl certificates, do they validate
    if not isinstance(ssl_cert_path, str):
        raise(TypeError("Path must be a string."))

    try:
        os.stat(ssl_cert_path)
    except OSError as error:
        logger.warning("tlscertpath does not exist. Exception: {0}".format(error))
        raise(OSError("Files do not exist Path: {0}".format(ssl_cert_path)))

    consul_ssl_cert = None
    consul_ca_cert = None
    consul_ssl_key  = None

    ca_regex = re.compile(
        r'.*(ca|chain).*',
        flags=re.IGNORECASE
    )
    cert_regex = re.compile(
        r'.*(cert).*',
        flags=re.IGNORECASE
    )
    cert_key_regex = re.compile(
        r'.*(key).*',
        flags=re.IGNORECASE
    )

    if os.path.isdir(ssl_cert_path):
        for ssl_file in os.listdir(ssl_cert_path):

            if ca_regex.match(ssl_file):
                consul_ca_cert = generate_path(ssl_cert_path, ssl_file)
            elif cert_regex.match(ssl_file):
                consul_ssl_cert = generate_path(ssl_cert_path, ssl_file)
            elif cert_key_regex.match(ssl_file):
                consul_ssl_key = generate_path(ssl_cert_path, ssl_file)
            else:
                pass



    ssl_path_dict = {
        'ssl_cert': consul_ssl_cert,
        'ssl_key': consul_ssl_key,
        'ca_chain': consul_ca_cert
    }

    return ssl_path_dict


def load_acl(path):
    if not isinstance(path, str):
        logger.error("Path Defined: {0}".format(path))
        raise(TypeError("Path must be a string."))

    if os.path.isdir(path):
        for file_ext in ('json'):
            test_path = os.path.join(path, 'acl.{0}'.format(file_ext))

            if os.path.isfile(test_path):
                path = test_path
                break

    if os.path.isfile(path):
        file_name, file_extension = os.path.splitext(path)

        with open(path, 'r') as file:
            try:
                if file_extension == '.json':
                    acl = json.loads(file.read())
                else:
                    raise(SyntaxError("acl configuration file must json."))

            except Exception as e:
                raise(SyntaxError("There is a syntax error in your acl configuration file. Exception: {0}".format(e)))
    else:
        logger.info("No acl defined for Consul connection")

    return acl


class ProcessHandler:

    def __init__(self, exit_on_term:bool=True):
        self.received_term_signal = self.received_signal = False
        self.exit_on_term = exit_on_term

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(sig, self.__handler)

    def __handler(self, signum, frame):
        self.last_signal     = signum
        self.received_signal = True

        if signum in [2, 3, 15]:
            # print 'is being terminated with signum: {1}.\n'.format(self.name, signum)
            self.received_term_signal = True

            if self.exit_on_term:
                exit(signum)
