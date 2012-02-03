#!/usr/bin/env python2.6

import os
import socket
import base64
import sys
import prctl
import signal
import struct
import traceback

from validate import validate_auth

SOCK_PATH = '/var/run/saslauthd/mux'
NUM_WORKERS = 5

def get_lenstring(sock):
    """Reads a length then a string from sock"""
    lenbytes = sock.recv(2, 0)
    (length,) = struct.unpack('!H', lenbytes)
    if length == 0:
        return ''
    value = sock.recv(length, 0)
    assert(len(value) == length)
    return value

def get_request(sock):
    """Return tuple of (user, passwd, service, realm)"""
    try:
        user = get_lenstring(sock)
        passwd = get_lenstring(sock)
        service = get_lenstring(sock)
        realm = get_lenstring(sock)
        return (user, passwd, service, realm)
    except Exception:
        traceback.print_exception(*sys.exc_info())
        return None

GOOD_RESP = struct.pack('!H', 2) + 'OK'
BAD_RESP = struct.pack('!H', 2) + 'NO'
def write_response(sock, response):
    if response:
        sock.sendall(GOOD_RESP)
    else:
        sock.sendall(BAD_RESP)

def child_work(servsock):
    while True:
        sock, addr = servsock.accept()
        try:
            request = get_request(sock)
            if request:
                resp = validate_auth(*request)
            else:
                resp = False
            write_response(sock, resp)
        except Exception:
            traceback.print_exception(*sys.exc_info())
        finally:
            sock.close()

def open_servsock(path):
    try:
        os.unlink(path)
    except:
        pass
    servsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    oldmask = os.umask(0)
    servsock.bind(path)
    os.chmod(path, 0777)
    os.umask(oldmask)
    servsock.listen(5)
    return servsock

def spawn_child(work):
    pid = os.fork()
    if (pid == 0):
        prctl.set_pdeathsig(signal.SIGHUP)
        try:
            work()
        except KeyboardInterrupt:
            print "{0:d}: exiting".format(os.getpid())
        sys.exit()
    return pid

if __name__ == '__main__':
    servsock = open_servsock(SOCK_PATH)
    children = []
    for x in xrange(NUM_WORKERS):
        children.append(spawn_child(lambda: child_work(servsock)))
    for child in children:
        os.waitpid(child, 0)
