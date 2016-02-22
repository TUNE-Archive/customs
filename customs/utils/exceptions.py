# -*- coding: utf-8; -*-


class ConsulSSLError(Exception):
    """
    Error raised when https is defined in --host argument or
    environmental variable and ssl certificates are not configured
    or defined
    """
    def __init__(self, msg):
        self.msg = "https scheme defined without any ssl certificates provided"

    def __str__(self):
        return self.msg
