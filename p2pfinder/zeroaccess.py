
# coding:utf-8
from socket import *
import struct
import zlib
import numpy as np
from lib.core.common import distinct
import sys
import binascii

import copy
ZEROACCESS_UDP_PORT_32 =16464
ZEROACCESS_UDP_PORT_64 =16465
reload(sys)
sys.setdefaultencoding("utf-8")
global count

class zeroaccessfinder():
    def __init__(self,udp_port=16464,ip='27.141.76.96',timeout=3):
        self.ip = ip.encode("utf-8").strip()
        self.udp_port = int(udp_port)
        self.timeout = timeout
        pass

    def set_port(self,udp_port=16465):
        self.udp_port = int(udp_port)
        pass

    def set_timeout(self,timeout):
        self.timeout = timeout
        pass

    def changeip(self,lst):
        a = lst[0]
        lst[0]=lst[3]
        lst[3]=a
        a = lst[1]
        lst[1]=lst[2]
        lst[2]=a
        return '.'.join(lst)

    def reverse(self,lst):
        return lst[::-1]

    def readbytes(self,decryptstr):
        ip_list =[]
        length = len(decryptstr)
        print "decryptstr length:%d"%length
        count =0
        crc32 = decryptstr[count:count+4]
        print 'crc32:%r'%self.reverse(crc32)
        count +=4
        retL = decryptstr[count:count + 4]
        print 'retL:%r'%self.reverse(retL)
        count += 4
        zero = decryptstr[count:count + 4]
        print 'zero:%r'%self.reverse(zero)
        count += 4
        ip_count = decryptstr[count:count + 4]
        try:
            ip_count = struct.unpack('I',ip_count)
        except  Exception, e:
            print e
        print 'ip_count:%d'%ip_count
        count += 4
        size = ip_count[0]*8+16
        while(count <size):
            # global count
            unit=decryptstr[count:count+8]
            count=count+8
            ip_int,time = struct.unpack('II', unit)
            ip = inet_ntoa(struct.pack('I', htonl(ip_int)))
            ip = ip.split('.')
            ip = self.changeip(ip)
            print ip
            if  ip not in ip_list:
                ip_list.append(ip+':'+str(self.udp_port))
        return ip_list

    def xorMessage(self,message, key):
        final_message = ''
        key_index = 0
        for byte_msg in message:
            byte_msg_int = ord(byte_msg)
            byte_msg_int ^= key[key_index]
            final_message += chr(byte_msg_int)
            key_index = (key_index + 1) % 4
            if key_index == 0:
                key_long = struct.unpack('I', struct.pack('4B', key[0], key[1], key[2], key[3]))[0]
                key_long = np.uint32(key_long)
                key_long = np.left_shift(key_long, 1) | np.right_shift(key_long, 31)
                key_int = int(key_long) & 0xffffffffL
                key = struct.unpack('4B', struct.pack('I', key_int))
        return final_message



    def buildZeroAccessGetLMessage(self):
        magic = 0xD9AEA1A8
        #magic = 0x85E246A8
        message = struct.pack('I4cIL',
                              0,
                              'L', 't', 'e', 'g',
                              0,
                              magic#0x85E246A8
                              )
        print 'message1:%r'%message

        crc_sum = zlib.crc32(message) & 0xffffffffL
        # crc_sum = self.crc2hex(message)
        print "%r"%crc_sum
        message = struct.pack('I4cIL',
                              crc_sum,
                              'L', 't', 'e', 'g',
                              0,
                              magic#0x85E246A8
                              )
        print 'message2:%r'%message
        key = [ord('2'), ord('p'), ord('t'), ord('f')]
        final_message = self.xorMessage(message, key)
        print 'final_message:%r'%final_message
        print repr(final_message)
        return final_message

    def unpackZeroAccessGetLMessage(self,decrpyptmessage):
        message = struct.unpack('I4cI',decrpyptmessage[:12])
        print 'CRC32:%r'%message[0]
        print 'retL:%r' % message[1]
        print 'null:%r' % message[2]#000
        message = struct.unpack('I4cI', decrpyptmessage[11:])
        print 'null:%r' % message[2]

        print 'message2:%r'%message
        key = [ord('2'), ord('p'), ord('t'), ord('f')]
        final_message = self.xorMessage(message, key)
        return final_message

    def sendDatagram(self):
        try:
            getL_message = self.buildZeroAccessGetLMessage()
            udpCliSock = socket(AF_INET, SOCK_DGRAM)
            udpCliSock.settimeout(self.timeout)
            ADDR = (self.ip, self.udp_port)
            udpCliSock.sendto(getL_message, ADDR)
            data, ADDR = udpCliSock.recvfrom(1024)
            key = [ord('2'), ord('p'), ord('t'), ord('f')]
            decryptmessage = self.xorMessage(data, key)
            print "decrypt retL message:%r" % decryptmessage
            udpCliSock.close()
            return decryptmessage
        except Exception, e:
            if self.udp_port==16464:
                print "first connect port 16464 :%s"%e
            elif self.udp_port == 16465:
                    print "second connect port 16465 :%s" % e
            udpCliSock.close()
            print 'udp closed'
            # traceback.print_exc()
            return

    def ZeroDecrypt(self,udpData):
        length = len(udpData)
        print length
        udpResultData=[]
        udpResultData.append(ord(udpData[0]))
        for i in range(length-1):
            re = ord(udpData[i])^ord(udpData[i-1])
            udpResultData.append(re)
        return "".join(map(chr, udpResultData))




def check(checkinfo, timeout=10):#ports is list  #2017.6.21  72.23.175.226 is ok
    # item = copy.deepcopy(ip)
    ip = checkinfo.get('ip')
    za_ip_list = []
    init_ip = ip.strip()

    botinfo = checkinfo

    all_result = []
    oldips = [init_ip]
    za = zeroaccessfinder(ip=init_ip)
    za.set_timeout(timeout)
    trytime = [0]

    botinfo['ip'] = init_ip
    botinfo['port'] = 16464
    botinfo['status'] = 'offline'
    decryptmessage = za.sendDatagram()
    if decryptmessage == None:
        za.set_port()
        decryptmessage = za.sendDatagram()
        if decryptmessage != None:
            botinfo['port'] = 16465
            botinfo['status'] = 'active'
            za_ip_list.extend(za.readbytes(decryptmessage))
    elif decryptmessage != None:
        botinfo['status'] = 'active'
        za_ip_list.extend(za.readbytes(decryptmessage))
    all_result.append(botinfo)

    for new_ip in za_ip_list:
        trytime[0] += 1
        print "trytime:%d" % trytime[0]
        new_ip = new_ip.split(':')[0]
        botinfo['ip'] = new_ip
        botinfo['port'] = 16464
        botinfo['status'] = 'offline'
        if new_ip not in oldips:
            za = zeroaccessfinder(ip=new_ip)
            decryptmessage = za.sendDatagram()
            oldips.append(new_ip)
            if decryptmessage == None:
                za.set_port()
                botinfo['port'] = 16465
                decryptmessage = za.sendDatagram()
                if decryptmessage != None:
                    botinfo['status'] = 'active'
                    za_ip_list.extend(za.readbytes(decryptmessage))
            elif decryptmessage != None:
                botinfo['status'] = 'active'
                za_ip_list.extend(za.readbytes(decryptmessage))
        all_result.append(botinfo)
    return distinct(all_result)

    result =[]
    if len(za_ip_list) > 0:
        za_ip_list = set(za_ip_list)
        print 'now bot size:%d' % len(za_ip_list)
    for ipinfo in za_ip_list:
        _ = ipinfo.split(':')
        ip = _[0]
        port = _[1]
        info = 'ip:%s,port:%s,receive:%s,type:%s' % (ip, port, 'Response message,please review  the code!', 'zeroaccessRAT')
        #info = {'ip':ip,'port':port,'type':'zeroaccessRAT'}
        result.append(info)
    if len(result) == 0:
        return None
    return result

if __name__ == "__main__":
    testdata ={'ip':'222.92.6.122','port':6718,'status':'offline'}#,{'ip':'115.249.216.130','port':5415,'id':'17000010'}
    import json
    print json.dumps(check(testdata),indent=2)
    # zeroaccessfinder().buildZeroAccessGetLMessage()