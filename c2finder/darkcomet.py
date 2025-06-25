# coding:utf-8
import socket
import re


def check(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        receive = (s.recv(1024))
        print "receive is ", receive
        s.close()
        # if receive.startswith('BF7CAB464EFB'):
        if re.search(r'^\w{1,12}',receive):
            return 'ip:%s,port:%d,receive:%s,type:%s' % (ip, port, (receive), 'darkcomet')
    except socket.error, socket.timeout:
        print 'timeout'
        s.close()
    return None
