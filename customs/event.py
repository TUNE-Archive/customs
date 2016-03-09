# -*- coding: utf-8; -*-
from .const import CONTAINER_EVENTS, IMAGE_EVENTS


class DockerEvent(object):
    def __init__(self, docker_id: str, image: str, status: str, epoch: int):
        self.docker_id  = docker_id
        self.image      = image
        self.epoch      = epoch
        self.status     = status
        self._name      = ''
        self._meta_data = {}

        if status in CONTAINER_EVENTS:
            self.type = 'container'

        elif status in IMAGE_EVENTS:
            self.type = 'image'

        else:
            self.type = 'unknown'

    def __str__(self) -> str:
        return "docker_id -> {0}\nimage -> {1},\nepoch -> {2},\nstatus -> {3},\ntype -> {4}".format(
            self.docker_id,
            self.image,
            self.epoch,
            self.status,
            self.type
        )

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def meta_data(self) -> dict:
        return self._meta_data

    @meta_data.setter
    def meta_data(self, value: dict):
        self._meta_data = value
