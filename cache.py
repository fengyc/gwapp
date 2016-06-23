# -*- coding:utf-8 -*-
# Copyright (c) 2016 Vinzor Co.,Ltd.
#
# cache
# 
# Created by fengyc at 16/6/23


class CacheEntry(object):
    def __init__(self, value, expired_at=None):
        self.value = value
        self.expired_at = expired_at


class Cache(object):
    def __init__(self, capacity=65536, overflows=None):
        self.cache = {}
        self.capacity = capacity
        self.overflows = overflows

    def clear(self):
        self.cache = {}
