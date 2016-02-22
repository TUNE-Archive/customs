# -*- coding: utf-8; -*-
from __future__ import unicode_literals

VERSION = "0.0.1"
CONTAINER_EVENTS = (
    'attach',
    'commit',
    'copy',
    'create',
    'destroy',
    'die',
    'exec_create',
    'exec_start',
    'export',
    'kill',
    'oom',
    'pause',
    'rename',
    'resize',
    'restart',
    'start',
    'stop',
    'top',
    'unpause'
)
IMAGE_EVENTS = ('delete', 'import', 'pull', 'push', 'tag', 'untag')
