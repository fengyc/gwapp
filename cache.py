# -*- coding:utf-8 -*-
# Copyright (c) 2016 Vinzor Co.,Ltd.
#
# cache
# 
# Created by fengyc at 16/6/23

import datetime


class CacheEntry(object):
    def __init__(self, value, expires):
        self.value = value
        self.created_at = datetime.datetime.now()
        self.expired_at = self.created_at + datetime.timedelta(seconds=expires)


class Cache(object):
    def __init__(self, capacity=65536, overflows=None, expires=120):
        self.entries = {}
        self.capacity = capacity
        self.overflows = overflows
        self.expires = expires

    def clear(self):
        self.entries = {}

    def put(self, key, value, expires=None):
        expires = expires or self.expires
        self.entries[key] = CacheEntry(value, expires)

    def get(self, key):
        return self.entries.get(key)