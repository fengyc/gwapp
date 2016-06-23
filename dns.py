# -*- coding:utf-8 -*-
# Copyright (c) 2016 Vinzor Co.,Ltd.
#
# dns
# 
# Created by fengyc at 16/6/23

import gevent.monkey; gevent.monkey.patch_dns()
import gevent
import socket
import logging

LOG = logging.getLogger(__file__)

HOST_CACHE = {}
CACHE_TIMEOUT = 120



def resolve(domain):
    if domain not in HOST_CACHE:
        LOG.debug('Resoling %s' % domain)
        addr = socket.gethostbyname(domain)
        HOST_CACHE[domain] = addr
        gevent.spawn_later()