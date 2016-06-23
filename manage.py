# -*- coding:utf-8 -*-
# Copyright (c) 2016 FENG Yingcai.
#
# manage.py
# 
# Created by fengyc at 16/6/23

import gevent.monkey; gevent.monkey.patch_all()
from gevent.server import StreamServer
from gevent.socket import create_connection
import os
import logging
import struct
import socket


LISTEN = os.environ.get('LISTEN') or '0.0.0.0:8080'
HOST = os.environ.get('HOST') or '127.0.0.1'
LOGLEVEL = os.environ.get('LOGLEVEL') or 'DEBUG'
MAXLENGTH = 4096

logging.basicConfig(level=LOGLEVEL)

LOG = logging.getLogger(__name__)


def unpack_auth_request(data):
    ver, nmethods = struct.unpack_from('!BB', data)
    methods_format = ('!{:B>' + nmethods + '}').format('')
    methods = struct.unpack_from(methods_format, data, offset=2)
    return ver, nmethods, methods


def pack_auth_response(ver=5, method=0):
    return struct.pack('!BB', ver, method)


def unpack_request(data):
    ver, cmd, rsv, atyp = struct.unpack_from('!BBBB', data)
    offset = 4
    if atyp == 1:   # IPv4
        dst_addr = struct.unpack_from('!4s', data, offset)
    if atyp == 3:   # Domain
        naddr = struct.unpack_from('!B', data, offset)
        offset += 1
        dst_addr = struct.unpack_from('!%ss' % naddr, data, offset)
        offset += naddr
    if atyp == 4:   # IPv6
        dst_addr = struct.unpack_from('!16s', data, offset)
        offset += 16
    dst_port = struct.unpack_from('!H', data, offset)
    return ver, cmd, rsv, atyp, dst_addr, dst_port


def pack_reply(ver, rep, rsv, atyp, bnd_addr, bnd_port):
    data = struct.pack('!BBBB', ver, rep, rsv, atyp)
    if atyp == 1:
        data2 = struct.pack('!4s', bnd_addr)
    elif atyp == 3:
        naddr = len(bnd_addr)
        data2 = struct.pack('!B%ss' % naddr, naddr, bnd_addr)
    elif atyp == 4:
        data2 = struct.pack('!16s', bnd_addr)
    data3 = struct.pack('!H', bnd_port)
    return data + data2 + data3


def inet_ntoa(addr):
    return socket.inet_ntoa(addr)


def inet_aton(addr):
    return socket.inet_aton(addr)



def forward(client, remote):
    remote.send(client.recv(MAXLENGTH))
    client.send(remote.recv(MAXLENGTH))

def handle(sock, client):
    """
    :param sock: socket
    :param client: client address
    :return:
    """
    LOG.debug('From %s' % client)
    # 1. auth request
    data = sock.recv(MAXLENGTH)
    auth_req = unpack_auth_request(data)
    auth_resp = (5, 0)
    data = pack_auth_response(*auth_resp)
    sock.send(data)
    # 2. request
    data = sock.recv(MAXLENGTH)
    req = unpack_request(data)
    rep = 0
    cmd = req[1]
    try:
        if cmd == 1: # connect
            remote_host = inet_ntoa(req[4])
            remote_port = req[5]
            remote = create_connection((remote_host, remote_port))
            local = remote.getsockname()
            bnd_addr = local[0]
            bnd_port = local[1]
        else:
            rep = 7     # command not support
    except socket.error:
        rep = 5     # connection refused
    data = pack_reply(5, rep, 0, 1, bnd_addr, bnd_port)
    sock.send(data)
    # 3. forward
    if rep == 0 and cmd == 1:
        forward(sock, remote)





if __name__ == '__main__':
    server = StreamServer(LISTEN, handle=handle)
    server.serve_forever()