# coding:utf-8
import socket
import struct




def check(ip, port, timeout = 3):

    # port_list = [3460,80,443,8080,8000]
    s1 = '\x00' * 0x100
    port = int(port)
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip , port))
        s.sendall(s1)
        receive = s.recv(0x100)

        if len(receive) != 0x100:
            s.close()
        else:
            receive = s.recv(0x4)

        if receive != '\xD0\x15\x00\x00':
            return False
        else:
            print 'poison %s:%s' % (ip, port)
            s.close()
            return True
        s.close()
        # if receive.startswith('CAP') or receive.endswith('[endof]'):
        #     print "find njRAT!"
        #     return 'ip:%s,port:%d,receive:%s,type:%s'%(ip,port,receive,'njRAT')
    except Exception, e:
        print 'timeout'
    # print struct.unpack('cBBcBBBcBBcBcBBB',receive[16:32])
    return None

# fobj = open('Poison','r')
# for line in fobj:
#     line = line.strip()
#     ports = []
#     ip = line.split(':')[0]
#     ports.append(line.split(':')[1])
#     check(ip,ports,3)
