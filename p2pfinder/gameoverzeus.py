# coding:utf-8

import sys
import re
import struct
import random
import socket
import md5
import zlib
from lib.core.common import distinct
import sys
reload(sys)
sys.setdefaultencoding('utf8')

def get_plugin_info():
    plugin_info = {
        "name": "gameoverzeusRATfinder",
        "info": "RAT version:V3.0",
        "level": "",
        "type": "p2p botnet",
        "author": "zzh@hansight",
        "url": "",
        "keyword": "c2:gameoverzeusRAT",
        "source": 1
    }
    return plugin_info


class ZeusGameoverError(Exception):
    pass


class ZeusGameover:
    """
    post process zeus gameover memdumps:

    - extract static peers
    - query static peers for config
    - enumerate p2p network
    """
    # number of static peers in memdump
    NUM_PEER_ENTRIES = 20

    # length of peer entry
    PEER_ENTRY_LEN = 45

    # senderID and incoming rc4 key
    SENDER_ID = "c9a370355e879b521171b90d22ea4f15f7b1b556".decode("hex")  # automatic generate
    # SENDER_ID = "c9a370355e879b521171b90d22ea4f15f7b1b565".decode("hex")

    # max response packet size
    MAX_PACKET_SIZE = 4096

    # socket timeout
    SOCK_TIMEOUT = 6

    # additional new peers threshold, percent
    NEW_PEER_THRES = 0.0

    def  getinfo(self,info):#ip:208.97.31.40,port:4950,key:8d398d3e7ddb14a8c2b221a2600483802c9c723d,status:offline
        key =info.split('key:')[1].split(',')[0]
        return key

    def __init__(self,peers):#peers={"ip":"212.251.104.12","port":4482,key:9c1c9572617db65bb8d3607592bed1a80d2cf2c4,status:offline"}
        # peers["key"] = self.getinfo(peers["info"]).decode('hex')
        self.static_peers=[]
        self.static_peers.append(peers)
        self.peers = self.enumerate_peers()


    def get_peer_array_offset(self):
        """
        extract peer array offset from memdump
        """
        # @TODO opcodes need further validation


        code_offset = re.search(r"\x8d\x8c\x24(.{4})\xe8.{4}\x6a.{1}\x8d\xbc\x24(.{4})", self.memdump_data)

        x = struct.unpack("I", code_offset.groups()[0])[0]  # 136
        y = struct.unpack("I", code_offset.groups()[1])[0]  # 198

        offset = y - x - 4
        return offset

    def get_peer(self, data, offset, quick=False):
        """
        extract a peer from a chunk of data
        """
        peer = {}
        peer["status"] = "offline"

        peer_entry = data[offset:offset + self.PEER_ENTRY_LEN]

        key = "".join(peer_entry[0x1:0x1 + 0x14])
        peer["key"] = key

        ip = ".".join(["%s" % ord(byte) for byte in peer_entry[0x15:0x15 + 0x4]])
        peer["ip"] = ip

        port = struct.unpack("H", "".join(peer_entry[0x19:0x19 + 0x2]))[0]
        peer["port"] = port

        if not quick:
            peer = self.query_peer_for_version(peer)

            if "tcp_port" in peer and self.memdump_rc4_key:
                peer = self.query_peer_for_config(peer)

        return peer

    def get_p2p_header(self, cmd):
        """
        generate a P2P header
        """
        # rand_byte = random.randint(1, 255)      # 1 byte, random value, not 0
        rand_byte = 0x44  # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now
        header = struct.pack("B", rand_byte)

        # ttl = random.randint(0, 255)            # 1 byte, TTL field or random value (when not used)
        ttl = 0x73  # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now
        header += struct.pack("B", ttl)

        junk_size = random.randint(0, 255)  # 1 byte, number of extra bytes to append to end of packet
        header += struct.pack("B", junk_size)

        header += struct.pack("B", cmd)  # 1 byte, cmd

        # for i in range(20):                     # SSID, 20 bytes
        #    ssid_byte = random.randint(0, 255)
        #    header += struct.pack("B", ssid_byte)
        header += "\xbb\x8c\x79\xa8\x5a\xf1\xe1\x94\xe0\x19\xae\x72\x56\x68\xfc\x1b\x42\xf7\xda\x3a"  # @TODO rand_byte, ttl, and ssid are related somehow, use hardcoded for now

        header += self.SENDER_ID  # senderID, 20 bytes

        return header, junk_size

    def rc4(self, key, in_buf):
        """
        rc4 encrypt/decrypt
        """
        out_buf = []
        i = 0
        j = 0
        S = self.ksa(key)

        for byte in in_buf:
            (i, j, S, K) = self.prga(i, j, S)
            new_byte = ord(byte) ^ K
            out_buf.append(chr(new_byte))

        return "".join(out_buf)

    def rc4_keystate(self, key_state, in_buf):
        """
        rc4 decrypted with exisiting KSA
        """
        out_buf = []
        i = ord(key_state[256])
        j = ord(key_state[257])
        S = [ord(byte) for byte in key_state[:256]]

        for byte in in_buf:
            (i, j, S, K) = self.prga(i, j, S)
            new_byte = ord(byte) ^ K
            out_buf.append(chr(new_byte))

        return "".join(out_buf)

    # the key-scheduling algorithm (KSA)
    def ksa(self, key):
        S = []
        # init to identity permutation
        for i in range(256):
            S.append(i)

        j = 0
        for i in range(256):
            # equal: j = (j + S[i] + ord(key[i % len(key)])) & 255
            j = (j + S[i] + ord(key[i % len(key)])) % 256
            S = self.swap(S, i, j)

        return S

    # swap list elements
    def swap(self, S, i, j):
        S[i], S[j] = S[j], S[i]

        return S

    # the pseudo-random generation algorithm (PRGA)
    def prga(self, i, j, S):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S = self.swap(S, i, j)
        K = S[(S[i] + S[j]) % 256]

        return (i, j, S, K)

    def parse_version_response(self, peer, response):
        """
        parse version response
        """
        # sanity check, make sure response command is 0x1
        if ord(response[0x3]) != 0x1:
            raise ZeusGameoverError("parse_version_response: bad response command: %x" % ord(response[0x3]))

        data = self.strip_response(response)

        peer["binary_ver"] = struct.unpack("I", "".join(data[0:4]))[0]
        peer["config_ver"] = struct.unpack("I", "".join(data[4:8]))[0]
        peer["tcp_port"] = struct.unpack("H", "".join(data[8:10]))[0]

        return peer

    def parse_config_response(self, peer, response):
        """
        parse config response
        """
        length = struct.unpack("I", "".join(response[0:4]))[0]
        rc4_decrypted_response = self.rc4_keystate(self.memdump_rc4_key, response[4:])
        plain = self.dexor(rc4_decrypted_response)

        # sanity checks
        # total length
        if length != len(plain):
            raise ZeusGameoverError("parse_config_response: bad total length")

        # config length -- subtract trailing rsa key at end
        calculated_len_of_conf = len(plain) - 256
        len_of_conf = struct.unpack("I", "".join(plain[20:24]))[0]
        if calculated_len_of_conf != len_of_conf:
            raise ZeusGameoverError("parse_config_response: bad config length")

        # md5 check
        calculated_hash_of_conf = "%04x%04x%04x%04x" % struct.unpack(">IIII", md5.new(
            "".join(plain[48:len(plain) - 256])).digest())
        hash_of_conf = "%04x%04x%04x%04x" % struct.unpack(">IIII", "".join(plain[32:32 + 16]))
        if calculated_hash_of_conf != hash_of_conf:
            raise ZeusGameoverError("parse_config_response: bad md5 check")

        # @TODO complete config parser
        # parse config
        peer["config"] = self.parse_config(plain)
        peer["config_len"] = len_of_conf

        return peer

    def parse_config(self, plain):
        """
        parse zeus gameover config

        @TODO complete config parser
        """
        config_version = struct.unpack("I", "".join(plain[28:32]))[0]

        # chop off StorageHeader and trailing rsa key
        items_blob = plain[48:-256]
        items_blob_len = len(items_blob)
        current_position = 0
        config = ""

        while current_position < items_blob_len:
            # get config entry pieces
            item_number = struct.unpack("I", "".join(items_blob[current_position:current_position + 4]))[0]
            item_type = struct.unpack("I", "".join(items_blob[current_position + 4:current_position + 8]))[0]
            item_size_packed = struct.unpack("I", "".join(items_blob[current_position + 8:current_position + 12]))[0]
            item_size_unpacked = struct.unpack("I", "".join(items_blob[current_position + 12:current_position + 16]))[0]
            item_data = "".join(items_blob[current_position + 16:current_position + 16 + item_size_packed])

            # decrypt data
            xor_key = (item_size_packed << 0x10) | (item_number & 0xFFFF) | (config_version << 8) & 0xffffffff
            xor_key_str = struct.pack("I", xor_key)
            data = []
            for i in range(len(item_data)):
                plain_byte = ord(item_data[i]) ^ ord(xor_key_str[i % 4])
                data.append(chr(plain_byte))

            # decompress if necessary
            if item_type & 0x1 == 1:
                data = zlib.decompress("".join(data), -15)

            # format entry
            config += "[start item number: %d, type: 0x%x, packed size: %d, unpacked size: %d]\n" % \
                      (item_number, item_type, item_size_packed, item_size_unpacked)
            config += "".join(data)
            config += "\n"
            config += "[end item number: %d]\n" % item_number

            current_position += 16 + item_size_packed

        return config

    def dexor(self, message):
        """
        dexor message, aka visual decrypt in zeus-talk
        """
        plain = []

        for i in range(len(message) - 1, 0, -1):
            plain_byte = ord(message[i]) ^ ord(message[i - 1])
            plain.append(chr(plain_byte))

        plain.append(message[0])
        plain.reverse()

        return plain

    def strip_response(self, response):
        """
        strip off p2p header and trailing junk bytes
        """
        junk_size = ord(response[0x2])
        data = response[0x2c:-junk_size]

        return data

    def get_static_peers_list(self):
        """
        return the list of static peers
        """
        return self.static_peers

    def get_peers_list(self):
        """
        return the list of peers
        """
        return self.peers

    def enumerate_peers(self):
        """
        enumerate p2p network, breadth first traversal
        """
        all_peers = []
        old_peers = []
        last_len = 0

        # init with static peers
        for peer in self.static_peers:
            all_peers.append(peer)
            old_peers.append(peer)

        while old_peers:
            # break if we're adding new peers too slowly
            percent = (len(all_peers) - last_len) / (len(all_peers) * 1.0)
            if percent < self.NEW_PEER_THRES:
                break
            last_len = len(all_peers)

            new_peers = []
            for old_peer in old_peers:
                peers = self.query_peer_for_peers(old_peer)

                if peers:
                    for peer in peers:
                        if peer not in all_peers:
                            all_peers.append(peer)
                            new_peers.append(peer)

            old_peers = new_peers

        return all_peers#[{'status': 'offline', 'ip': '74.203.254.118', 'port': 6630, 'key': '\xc0F\xb4?\xbc\xec$u\x83\x10\x83\xaaV\xae\xf3\xd5\xb7,\xed\xa6'}]

    def get_junk(self, junk_size):
        """
        get junk bytes
        """
        junk = ""
        for i in range(junk_size):  # junk_size junk bytes
            junk_byte = random.randint(0, 255)
            junk += struct.pack("B", junk_byte)

        return junk

    def query_peer_for_peers(self, peer):
        """
        query peer for its peers, 0x02 command
        """
        p2p_header, junk_size = self.get_p2p_header(0x02)

        # 0x02 cmd
        data = peer["key"]  # reqID, 20 bytes
        peer['status'] = 'offline'

        for i in range(8):  # randomFill, 8 bytes
            random_fill = random.randint(1, 255)  # non-zero random bytes
            data += struct.pack("B", random_fill)

        junk = self.get_junk(junk_size)

        command = p2p_header + data + junk

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.SOCK_TIMEOUT)

        encrypted_command = self.rc4(peer["key"], command)

        response = ""
        try:
            sock.sendto(encrypted_command, (peer["ip"], peer["port"]))
            response = sock.recv(self.MAX_PACKET_SIZE)
        except:
            pass

        sock.close()

        peers = []
        if response:
            peer['status'] = 'alive'
            decrypted_response = self.rc4(self.SENDER_ID, response)
            peers = self.parse_peers_response(decrypted_response)

        return peers

    def parse_peers_response(self, response):
        """
        parse peers response
        """
        peers = []
        # sanity check, make sure response command is 0x3
        if ord(response[0x3]) != 0x3:
            raise ZeusGameoverError("parse_peers_response: bad response command: %x" % ord(response[0x3]))

        data = self.strip_response(response)

        for i in range(len(data) / self.PEER_ENTRY_LEN):
            offset = i * self.PEER_ENTRY_LEN
            peer = self.get_peer(data, offset, quick=True)
            peers.append(peer)

        return peers

    def format_peer_entry(self, peer):
        """
        pretty format a peer entry
        """
        entry = []

        entry += ["    ip: %s, udp port: %d, rc4 key: %s" % \
                  (peer["ip"], peer["port"], "".join(peer["key"]).encode('hex'))]

        if "binary_ver" in peer:
            entry += ["    binary version: %d, config version: %d, tcp port: %d" % \
                      (peer["binary_ver"], peer["config_ver"], peer["tcp_port"])]

        if "config" in peer:
            entry += ["    config saved (%d actual bytes)" % peer["config_len"]]

        entry += [""]

        return entry

    def format_peers(self,peers):
        if len(peers) <=1:
            return
        for peer in peers:
            peer['key'] = peer['key'].encode('hex')
        return peers

# if __name__ == "__main__":
def check(checkinfo):
    try:
        checkinfo['key'] = checkinfo['key'].decode('hex')
        zeus_gameover = ZeusGameover(peers=checkinfo)
    except ZeusGameoverError as msg:
        print "Error: %s" % msg
        sys.exit(1)

    peers = zeus_gameover.get_peers_list()
    peers = zeus_gameover.format_peers(peers)
    if peers:
        return distinct(peers)

    # result = []
    # for peer in peers:
    #     line = 'ip:%s,port:%s,key:%s,status:%s' % (peer['ip'],str( peer['port']), peer['key'].encode('hex'), peer['status'])
    #     print line
    #     if line not in result:
    #         result.append(line)
    # result =list(set(result))
    # if len(result) <= 1:
    #     return None
    # return result

if __name__ == "__main__":
    peers ={'ip':'74.96.168.126','port':6710,'key':'c2056f859dd9fdf008507a637a0da568d16f825b','status':'offline'}
    info = check(checkinfo=peers)
    import json
    print json.dumps(info,indent=2)
