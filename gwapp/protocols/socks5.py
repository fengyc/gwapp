# -*- coding:utf-8 -*-
# Copyright (c) 2016 FENG Yingcai
#
# socks5
# 
# Created by fengyc at 16/6/23

import gevent.monkey; gevent.monkey.patch_socket()
import gevent
from gevent.server import StreamServer
from gevent.socket import create_connection
import socket
import struct
import logging
import six

SOCKS5_VER = 5

SOCKS5_METHODS = {
    0x00: 'NO AUTHENTICATION REQUIRED',
    0x01: 'GSSAPI',
    0x02: 'USERNAME/PASSWORD',
    0x03: 'IANA ASSIGNED',  # 0x03 ~ 0x7f
    0x80: 'RESERVED FOR PRIVATE METHODS',   # 0x80 ~ 0xfe
    0xff: 'NO ACCEPTABLE METHODS'
}

SOCKS5_ATYPS = {
    0x01: 'IPv4',
    0x03: 'Domain',
    0x04: 'IPv6',
}

SOCKS5_CMD = {
    0x01: 'CONNECT',
    0x02: 'BIND',
    0x03: 'UDP'
}

SOCKS5_ERRORS = {
    0x00: "Success",
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

SOCKS5_DEFAULT_PORT = 1080

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(msg)s")
LOG = logging.getLogger(__file__)


class NegotiateRequestPackage(object):
    def __init__(self, ver=5, methods=(0,)):
        self.ver = ver,
        self.methods = methods,
        self.nmethod = len(methods),

    def pack(self):
        data1 = struct.pack('!BB', self.ver, self.nmethod)
        methods_fmt = ('!{:B>%s}' % self.nmethod).format('')
        data2 = struct.pack(methods_fmt, *self.methods)
        return data1 + data2

    @staticmethod
    def unpack(data):
        ver, nmethod = struct.unpack_from('!BB', data)
        methods_fmt = ('!{:B>%s}' % nmethod).format('')
        methods = struct.unpack_from(methods_fmt, data, 2)
        return NegotiateRequestPackage(ver, methods)


class NegotiateResponsePackage(object):
    def __init__(self, ver=5, method=0):
        self.ver = ver
        self.method = method

    def pack(self):
        return struct.pack('!BB', self.ver, self.method)

    @staticmethod
    def unpack(data):
        ver, method = struct.unpack_from('!BB', data)
        return NegotiateResponsePackage(ver, method)


def _pack_addr(atyp, addr):
    if atyp == 1:
        data = struct.pack('!4s', addr)
    elif atyp == 3:
        ndst_addr = len(addr)
        data = struct.pack('!B%ss' % ndst_addr, ndst_addr, addr)
    elif atyp == 4:
        data = struct.pack('!16s', addr)
    return data


def _unpack_addr(atyp, data, offset):
    if atyp == 1:
        addr, = struct.unpack_from('!4s', data, offset)
        offset += 4
    elif atyp == 3:
        naddr, = struct.unpack_from('!B', data, offset)
        addr, = struct.unpack_from('!%ss' % naddr, data, offset + 1)
        offset += 1 + naddr
    elif atyp == 4:
        addr, = struct.unpack_from('!16s', data, offset)
        offset += 16
    return (addr, offset)


class RequestPackage(object):
    def __init__(self, ver=5, cmd=0, rsv=0, atyp=1, dst_addr=b'\x00\x00\x00\x00', dst_port=0):
        self.ver = ver
        self.cmd = cmd
        self.rsv = rsv
        self.atyp = atyp
        self.dst_addr = dst_addr
        self.dst_port = dst_port

    def pack(self):
        data1 = struct.pack('!BBBB', self.ver, self.cmd, self.rsv, self.atyp)
        data2 = _pack_addr(self.atyp, self.dst_addr)
        data3 = struct.pack('!H', self.dst_port)
        return data1 + data2 + data3

    @staticmethod
    def unpack(data):
        ver, cmd, rsv, atyp = struct.unpack_from('!BBBB', data)
        dst_addr, offset = _unpack_addr(atyp, data, 4)
        dst_port, = struct.unpack_from('!H', data, offset)
        return RequestPackage(ver, cmd, rsv, atyp, dst_addr, dst_port)


class ReplyPackage(object):
    def __init__(self, ver=5, rsp=0, rsv=0, atyp=1, bnd_addr=b'\x00\x00\x00\x00', bnd_port=0):
        self.ver = ver
        self.rsp = rsp
        self.rsv = rsv
        self.atyp = atyp
        self.bnd_addr = bnd_addr
        self.bnd_port = bnd_port

    def pack(self):
        data1 = struct.pack('!BBBB', self.ver, self.rsp, self.rsv, self.atyp)
        data2 = _pack_addr(self.atyp, self.bnd_addr)
        data3 = struct.pack('!H', self.bnd_port)
        return data1 + data2 + data3

    @staticmethod
    def unpack(data):
        ver, rsp, rsv, atyp = struct.unpack_from('!BBBB', data)
        bnd_addr, offset = _unpack_addr(atyp, data, 4)
        bnd_port, = struct.unpack_from('!H', data, offset)
        return ReplyPackage(ver, rsp, rsv, atyp, bnd_addr, bnd_port)


class UDPRequestPackage(object):
    def __init__(self, rsv=b'\x00\x00', frag=0, atyp=1, dst_addr=b'\x00\x00\x00\x00', dst_port=0, data=b''):
        self.rsv = rsv
        self.frag = frag
        self.atyp = atyp
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.data = data

    def pack(self):
        data1 = struct.pack('!2sBB', self.rsv, self.frag, self.atyp)
        data2 = _pack_addr(self.atyp, self.dst_addr)
        data3 = struct.pack('!H', self.dst_port)
        return data1 + data2 + data3 + self.data

    @staticmethod
    def unpack(data):
        rsv, frag, atyp = struct.unpack_from('!2sBB', data)
        dst_addr, offset = _unpack_addr(atyp, data, 4)
        dst_port, = struct.unpack_from('!H', data, offset)
        return UDPRequestPackage(rsv, frag, atyp, dst_addr, dst_port, data[offset:])


class Socks5Server(StreamServer):
    def __init__(self, *args, **kwargs):
        super(Socks5Server, self).__init__(*args, **kwargs)
        LOG.debug('Socks5Server is serving at %s' % (self.address,))

    @staticmethod
    def forward(address, source, dest, callback=None):
        source_addr = source.getpeername()
        dest_addr = dest.getpeername()
        with source, dest:
            try:
                while True:
                    if source._closed or dest._closed:
                        break
                    data = source.recv(4096)
                    if not data:
                        break
                    dest.sendall(data)
            except OSError:
                if source._closed:
                    LOG.debug('%s -> %s is closed' % (address, source_addr))
                if dest._closed:
                    LOG.debug('%s -> %s is closed' % (address, dest_addr))
            except:
                LOG.exception('%s -> unable to forward %s to %s' % (str(address), source_addr, dest_addr))
        if callable(callback):
            callback(address)

    @staticmethod
    def forward_completed_callback(address):
        LOG.info('%s -> disconnected' % str(address))

    def handle(self, sock, address):
        LOG.debug('%s -> connecting' % str(address))

        # 1. negotiation
        LOG.debug('%s -> negotiating' % str(address))
        req = NegotiateRequestPackage.unpack(sock.recv(4096))
        # TODO add negotiation support here
        resp = NegotiateResponsePackage()
        sock.sendall(resp.pack())

        # 2. request
        LOG.debug('%s -> request' % str(address))
        req = RequestPackage.unpack(sock.recv(4096))
        resp = ReplyPackage()
        if req.cmd == 1:    # connect
            try:
                remote_sock = create_connection((req.dst_addr.decode(), req.dst_port))
                resp.rsp = 0    # success
                resp.bnd_addr = socket.inet_aton(remote_sock.getsockname()[0])
                resp.bnd_port = remote_sock.getsockname()[1]
            except Exception as ex:
                LOG.exception('%s -> unable to connect %s' % (str(address), str((req.dst_addr.decode(), req.dst_port))))
                resp.rsp = 5    # connection refused
        else:
            resp.rsp = 7    # not support
        sock.sendall(resp.pack())

        # 3. forward
        if resp.rsp == 0:
            forwarders = (gevent.spawn(Socks5Server.forward, address, sock, remote_sock, Socks5Server.forward_completed_callback),
                              gevent.spawn(Socks5Server.forward, address, remote_sock, sock))
            gevent.joinall(forwarders)
