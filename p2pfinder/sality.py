# -*- coding: utf-8 -*-
from scapy.all import  *#sudo apt-get install python-scapy or pip install scapy
from socket import *
# from lib.utils.config import ConfigFileParser
import binascii

# from itertools import groupby
# from operator import itemgetter
#
# import pandas as pd
# import dpkt #伪造报文
from lib.core.common import distinct
from lib.core.data import paths

def get_plugin_info():
    plugin_info = {
        "name": "salityRATfinder",
        "info": "RAT version:V4.0,common udp port:3288-18075",
        "level": "",
        "type": "p2p botnet",
        "author": "",
        "url": "",
        "keyword": "c2:salityRATfinder",
        "source": 1
    }
    return plugin_info


class salityfinder():
    def __init__(self,udp_src_port=0,udp_dst_port=0,dst_ip=''):
        self.dst_ip = dst_ip.strip()
        self.udp_src_port = int(udp_src_port)
        self.udp_dst_port = int(udp_dst_port)
        pass

    def portisleagl(self,port):
        if port >=3288 and port <= 18075:
            return True
        else:
            return False

    def set_src_port(self,udp_src_port):
        if self.portisleagl(udp_src_port):
            self.udp_src_port = udp_src_port
        else :
            print "udp_src_port is not the sality port range(3288-18075)"
            return
        pass

    def set_dst_port(self,udp_dst_port):
        if self.portisleagl(udp_dst_port):
            self.udp_dst_port = udp_dst_port
        else :
            print "udp_dst_port is not the sality port range(3288-18075)"
            return
        pass

    def changeip(self,lst):
        a = lst[0]
        lst[0]=lst[3]
        lst[3]=a
        a = lst[1]
        lst[1]=lst[2]
        lst[2]=a
        return '.'.join(lst)

    def set_dst_ip(self,dst_ip):
        self.dst_ip = dst_ip
        pass

    def reverse(self,lst):
        return lst[::-1]

    def readbytes(self, encryptstr):
        length = len(encryptstr)
        if length > 20:
            print "decryptstr length:%d" % length
            count = 0
            hash = encryptstr[count:count + 2]
            print 'hash:%r' % self.reverse(hash)
            count += 2
            size = encryptstr[count:count + 2]
            public_key = hash +size
            print 'public_key%r:'%public_key
            size = int(struct.unpack('h', size)[0])
            print 'size:%r' % size
            count += 2

            encmessage = encryptstr[count:length]
            message = self.salityDecrypt(encmessage,public_key)
            count = 0
            version = message[count:count + 1]
            version = struct.unpack('B', version)[0]
            print 'version:%r' % version
            count += 1
            pack_id =  message[count:count + 4]
            pack_id =  struct.unpack('I', pack_id)[0]
            print 'url pack sequence ID:%r' % pack_id
            count += 4
            message_type = message[count:count + 1]
            message_type = int (struct.unpack('B', message_type)[0])
            print 'message_type:%r' % message_type
            count += 1
            if message_type ==2 :
                ip = message[count:count + 4]
                ip = struct.unpack('I', ip)
                ip = inet_ntoa(struct.pack('I', htonl(ip[0])))
                ip = ip.split('.')
                ip = self.changeip(ip)
                print 'ip:%s'%ip
                global count
                count += 4
                port = message[count:count + 2]
                port = int (struct.unpack('h', port)[0])
                count += 2
                print 'port:%d' % port
                ID = message[count:count + 4]
                ID = int(struct.unpack('I', ID)[0])
                print 'ID:%d' % ID
                return {'ip':ip,'port':port,'id':ID}
        else:
            return


    def salityDecrypt(self,data,key):
        # if the data is a string, convert to hex format.
        if (type(data) is type("string")):
            tmpData = data
            data = []
            for tmp in tmpData:
                data.append(ord(tmp))

        # if the key is a string, convert to hex format.
        if (type(key) is type("string")):
            tmpKey = key
            key = []
            for tmp in tmpKey:
                key.append(ord(tmp))

        # the Key-Scheduling Algorithm
        x = 0
        box = list(range(256))
        for i in range(256):
            x = (x + box[i] + key[i % len(key)]) % 256
            box[i], box[x] = box[x], box[i]

        # the Pseudo-Random Generation Algorithm
        x = 0
        y = 0
        out = []
        for c in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(c ^ box[(box[x] + box[y]) % 256])

        result = ""
        printable = True
        for tmp in out:
            if (tmp <0x21 or tmp > 0x7e):
                # there is non-printable character
                printable = False
                break
            result += chr(tmp)
        # return result
        if (printable == False):
            result = ""
            # convert to hex string
            for tmp in out:
                result += "{0:02X}".format(tmp)
        print "result:%r"%result
        return binascii.a2b_hex(result)

    def sendDatagram(self,sendcount=3,load=''):
        if self.dst_ip and self.udp_dst_port  and self.udp_src_port:
            pass
        else:
            print 'please input the dst_ip or udp_dst_port or udp_src_port'
            return
        newip=[]
        failcount = [0, ]
        for  i in range(sendcount):# now 100 is my guess, need some data prove
            try:
                udpCliSock = socket(AF_INET, SOCK_DGRAM)
                udpCliSock.bind(('',self.udp_src_port))
                udpCliSock.settimeout(3)
                ADDR = (self.dst_ip, self.udp_dst_port)
                udpCliSock.sendto(load, ADDR)
                if failcount[0] >20:
                    return newip
                data, ADDR = udpCliSock.recvfrom(1024)
                ipi = self.readbytes(data)# return {'ip':ip,'port':port,'id':id}
                if ipi :
                    ipi['status'] = 'active'
                print ipi['ip'],ipi['port'],ipi['id'],ipi['status']
                udpCliSock.close()
                newip.append(ipi)
                failcount[0] =0
            except Exception, e:
                print "connect to ip:%s port:%d failed,reason is  %s"%(self.dst_ip,self.udp_dst_port,e)
                udpCliSock.close()
                failcount[0] = failcount[0] +1
                # traceback.print_exc()

        return newip

    def get_urlpack(self,replayfilepath  ):
        init_packet =[]
        #try:
        packets = rdpcap(replayfilepath)
        #except Exception ,e:
            #print e
        for p in packets:
            item = {}
            for f in p.payload.fields_desc:
                if f.name == 'src' or f.name == 'dst':
                    ct = conf.color_theme
                    vcol = ct.field_value
                    fvalue = p.payload.getfieldval(f.name)
                    reprval = f.i2repr(p.payload, fvalue)
                    item[f.name] = reprval
            for f in p.payload.payload.fields_desc:
                if f.name == 'sport' or f.name == 'dport':
                    ct = conf.color_theme
                    vcol = ct.field_value
                    fvalue = p.payload.getfieldval(f.name)
                    reprval = f.i2repr(p.payload, fvalue)
                    print "%s : %s" % (f.name, reprval)
                    item[f.name] = repr(fvalue)
            for f in p.payload.payload.payload.fields_desc:
                if f.name == 'load' :
                    fvalue = p.payload.payload.payload.getfieldval(f.name)
                    reprval = fvalue
                    # readbytes(fvalue)#test readbytes
                    item[f.name] = reprval
            init_packet.append(item)
        return init_packet

# def distinct(items):
#     from itertools import compress
#     mask = (~pd.Series(map(itemgetter('ip'), items)).duplicated()).tolist()
#     return list(compress(items, mask))

# urlpack = get_urlpack()

def check(checkinfo):#in c2 botnet ports is port list;in p2p botnet ip is {ip:ip1,port:port2}

    sa = salityfinder()
    path = os.path.join(paths.ROOT_PATH ,'sample/pcap/sality_sample.pcap')
    sality_pcap = sa.get_urlpack(replayfilepath =path)
    # sality_pcap = sa.get_urlpack(replayfilepath =paths.SALITY_PCAP)
    init_src_port = int(sality_pcap[0]['sport'])
    load = sality_pcap[0]['load']
    sa_ip_list=[]
    oldips = [checkinfo]

    trytime = 0
    # for init_ip_port in item:# init entry point
    init_dst_ip = checkinfo.get('ip')
    init_dst_port = int(checkinfo.get('port'))
    sa.set_dst_ip(init_dst_ip)
    sa.set_dst_port(init_dst_port)
    sa.set_src_port(init_src_port)
    reponse = sa.sendDatagram(load=load)
    if reponse :
        sa_ip_list.extend(reponse)  #[{'ip':ip,'port':port,'ID':ID}]
    for new_ip in sa_ip_list:
        global trytime
        trytime += 1
        print "trytime:%d"%trytime
        if new_ip not in oldips:
            sa.set_dst_port(new_ip['port'])
            sa.set_dst_ip(new_ip['ip'])
            reponse = sa.sendDatagram(load=load)
            if reponse:
                sa_ip_list.extend(reponse)
            oldips.append(new_ip)
    return distinct(sa_ip_list)

    # set_ip = []
    # for ipi in sa_ip_list:
    #     line = 'ip:%s,port:%d,id:%d'%(ipi['ip'],ipi['port'],ipi['id'])
    #     if line not in set_ip:
    #         set_ip.append(line)
    # sa_ip_list = set(set_ip)
    # if len(sa_ip_list) >0:
    #     return  list(sa_ip_list)
    # return None

if __name__ == "__main__":
    testdata ={'ip':'222.92.6.122','port':6718,'id':'17000010'}#,{'ip':'115.249.216.130','port':5415,'id':'17000010'}
    import json
    print json.dumps(check(testdata),indent=2)