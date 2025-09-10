#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
from lib.utils.logger import logger
from lib.utils.config import ConfigFileParser

def distinctent(ent_file_path):
    ent_lists = []
    for ent in open(ent_file_path):
        ent_lists.append(ent)
    return list(set(ent_lists))

def GOZextractkey(infostr):
    return infostr.split('key:')[1].split(',')[0]

def SALITYextractkey(infostr):
    return infostr.split('ID:')[1].split(',')[0]

def init_file():
    # mongo_ent = ConfigFileParser().P2pEntPointMongo()
    # default_ent = ConfigFileParser().DefaultP2pEntPoint()
    file_ent = ConfigFileParser().P2pEntPointFile()

    p2plist = {'zeroaccess': [], 'gameoverzeus': [], 'sality': []}

    # todolist
    # if mongo_ent or (not mongo_ent):
    #     logging.info('p2p entrance not from mognodb...')
    logger.info('开始获取P2P僵尸网络的历史IP地址')
    if file_ent:
        for ratinfo in distinctent(file_ent):
            ratinfo = json.loads(ratinfo)
            p2pname = ratinfo.get("RAT_info").get("RATfinderName").split('RAT')[0].strip()
            if p2pname == 'zeroaccess':

                p2plist[p2pname].append({'ip':ratinfo['ip'],'port':int(ratinfo['port'])})
            if p2pname == 'gameoverzeus':
                p2plist[p2pname].append({'ip':ratinfo['ip'],'port':int(ratinfo['port']),'key':GOZextractkey(ratinfo['info'])})
            if p2pname == 'sality':
                p2plist[p2pname].append({'ip':ratinfo['ip'],'port':int(ratinfo['port']),'id':SALITYextractkey(ratinfo['info'])})
                # print ratinfo['ip']
    logger.info('开始获取P2P僵尸网络的历史IP地址')
    return p2plist

if __name__ == '__main__':
    print json.dumps(init_file(),indent=2)



