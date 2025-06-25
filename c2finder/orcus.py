# coding:utf-8
import socket
import struct



def check(ip, port, timeout = 3):

    # port_list = [3460,80,443,8080,8000]
    # for port in ports:
    s1 = '\x16\x03\x01\x00\x72\x01\x00\x00\x6e\x03\x01\x5a\x28\xb2\x14\x37\xc9\xc0\xf1\xbc\x81\x95\xb8\xfa\x37\xd2\x6b\x0f\x82\xdb\x33\x95\x9c\x02\x8c\x27\xa3\xf2\x97\xff\x92\x67\xe3\x00\x00\x18\x00\x2f\x00\x35\x00\x05\x00\x0a\xc0\x13\xc0\x14\xc0\x09\xc0\x0a\x00\x32\x00\x38\x00\x13\x00\x04\x01\x00\x00\x2d\xff\x01\x00\x01\x00\x00\x00\x00\x14\x00\x12\x00\x00\x0f\x57\x49\x4e\x2d\x49\x51\x51\x47\x48\x43\x32\x50\x4a\x54\x4f\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00'
    # s1 = '0'
    port = int(port)
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip , port))
        s.send(s1)
        receive = s.recv(2048)
        if receive.startswith('\x16\x03\x01'):
            print 'Ocurs %s:%s' % (ip,port)
            s.close()
            return True
        # else:
        #     print receive.encode('hex')
        s.close()
    except Exception, e:
        # print e
        print 'timeout'
    return None

# fobj = open('Orcus','r')
# for line in fobj:
#     line = line.strip()
#     ports = []
#     ip = line.split(':')[0]
#     ports.append(line.split(':')[1])
#     check(ip,ports,3)
