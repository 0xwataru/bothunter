import socket
# import re
def check(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send('\r\n')
        receive = s.recv(10)
        print "receive is ", receive
        s.close()
        if receive.startswith('X\r\n'):
            return 'ip:%s,port:%d,receive:%s,type:%s' % (ip, port, repr(receive), 'xtremeRAT')
    except socket.error, socket.timeout:
        print 'timeout'
        s.close()
    return None