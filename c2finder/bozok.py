# coding:utf-8
import socket
import struct



def check(ip, port, timeout = 3):

    # port_list = [3460,80,443,8080,8000]

        # s1 = '\x8e\x00\x00\x00\x00\x7c\x00\x69\x63\x72\x6f\x73\x6f\x66\x74\x2e\x6d\x72\x62\x61\x73\x69\x63\x2e\x63\x6f\x00\x7c\x00\x61\x00\x64\x00\x6d\x00\x69\x00\x6e\x00\x7c\x00\x61\x00\x75\x00\x62\x00\x6f\x00\x6b\x00\x7c\x00\x45\x00\x4e\x00\x55\x00\x7c\x00\x35\x00\x7c\x00\x31\x00\x2e\x00\x35\x00\x2e\x00\x31\x00\x7c\x00\x30\x00\x7c\x00\x32\x00\x7c\x00\x77\x00\x77\x00\x77\x00\x73\x00\x74\x00\x40\x00\x41\x00\x64\x00\x6d\x00\x69\x00\x6e\x00\x7c\x00\x33\x00\x37\x00\x33\x00\x7c\x00\x4d\x00\x69\x00\x63\x00\x72\x00\x6f\x00\x73\x00\x6f\x00\x66\x00\x74\x00\x20\x00\x57\x00\x6f\x00\x72\x00\x64\x00\x00'
        # s1 ='sddsd'
    port = int(port)
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip , port))
        receive = s.recv(2048)
        # print receive
        # print receive.encode('hex')
        length = ord(receive[0]) + ord(receive[1]) * 256 + ord(receive[2]) * 256 * 256 + ord(receive[3]) * 256 * 256 * 256 * 256
        if length == len(receive) - 4:
            i = 4
            # each character of password is seperated by a zero byte
            while i < len(receive):
                if ord(receive[i]) != 0:
                    break
                i += 2
            if i >= len(receive):
                print 'Bozok %s:%s' % (ip,port)
                s.close()
                return True
        # print length,' ',len(receive)
        s.close()
    except Exception, e:
        # print e
        print 'timeout'
    return None

# fobj = open('Bozok','r')
# for line in fobj:
#     line = line.strip()
#     ports = []
#     ip = line.split(':')[0]
#     ports.append(line.split(':')[1])
#     check(ip,ports,3)
