# coding:utf-8
import socket


def check(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        receive = (s.recv(10))
        print "receive is ", receive
        s.close()
        if receive.startswith('0' * 10):  # 64 * '0' is the most
            return 'ip:%s,port:%d,receive:%s,type:%s' % (ip, port, (receive), 'nuclear')
    except socket.error, socket.timeout:
        print 'timeout'
        s.close()
    return