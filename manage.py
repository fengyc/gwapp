# -*- coding:utf-8 -*-
# Copyright (c) 2016 FENG Yingcai.
#
# manage.py
# 
# Created by fengyc at 16/6/23

from socks5 import Socks5Server
import logging

logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    server = Socks5Server(('127.0.0.1', 5000))
    server.serve_forever()