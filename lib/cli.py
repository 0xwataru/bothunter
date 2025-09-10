#!/usr/bin/env python
# -*- coding: utf-8 -*-



import os.path
import traceback
import logger
import sys
from lib.core.data import paths
from lib.core.common import setPaths
from lib.kafka_ import *
from lib.mongo_ import  *
from lib.shodan_ import *
from lib.file_ import *
from lib.utils.logger import logger


def c2check():
    checkedlist = []
    searchfliter = 'category:malware'
    api =init_shodan()
    for ratinfo in shodan_search(api,searchfliter):
        # for ratinfo in [{"ratname":'netbus',"ip":"161.111.232.10", "port":12345,'type':'c2 botnet'}]:
        ratname = ratinfo['ratname']
        if ratname == 'zeroaccess':
            continue
        ip = ratinfo['ip']
        port = ratinfo['port']
        try:
            plugin_res = __import__(ratname)
        except Exception, e:
            logging.error(e)
            continue
        res = plugin_res.check(ip, int(port))
        if res:
            print ip
            checkedlist.append(ratinfo)
    return checkedlist


def p2pcheck():
    p2plist = init_file()
    all_p2p_node = []
    for ratname in p2plist.keys():
        checkedips = []
        for paramdict in p2plist[ratname]:  # paradict is dict #p2p check function's param is a dict {'ip':ip,'port':port,other:other}
            # logger.info('开始探测{}IP:{}端口:{}'.format(ratname,paramdict.get('ip'),paramdict.get('port')))
            plugin_res = __import__(ratname)
            if paramdict['ip'] not in checkedips:
                res = plugin_res.check(paramdict)  # return value is [{'ip':ip,'port':port,other:other}]
                if res:
                    for botinfo in res:
                        if botinfo['ip'] not in checkedips:
                            botinfo['ratname'] = ratname
                            botinfo['type'] = 'p2p botnet'
                            checkedips.append(botinfo['ip'])
                            logger.info('IP:%s端口:%s为激活状态' % (paramdict.get('ip'), paramdict.get('port')))
                            all_p2p_node.extend(res)
                            print("*"*6)
                            print(all_p2p_node)
                            print("*"*6)


                    break  # one entry point is ok
    return all_p2p_node

def p2pfirstcheck():
    pass



def main():
    """
    Main function of own_hunter when running from command line.
    """
    try:
        paths.ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        try:
            os.path.isdir(paths.ROOT_PATH)
        except UnicodeEncodeError:
            errMsg = "your system does not properly handle non-ASCII paths. "
            errMsg += "Please move the project root directory to another location"
            logger.error(errMsg)
            raise SystemExit
        setPaths()
        """
        add the c2finder and p2pfinder scripts to the sys.path.
        """
        sys.path.append(paths.C2_PATH)
        sys.path.append(paths.P2P_PATH)
    except Exception:
        print traceback.format_exc()
        logger.warning('It seems like you reached a unhandled exception, please report it to author\'s email or raise a issue via:<https://github.com/Xyntax/POC-T/issues/new>.')
    # kafkasender,topic = init_kafka()
    # mongodb = init_mongodb()
    # for ratinfo in c2check():
    #     mongodb.insert(mongo_formatter(ratinfo['ip'],ratinfo['port'],ratinfo['ratname'],ratinfo['type']))
    #     pushdata(kafkasender,kafka_formatter(ratinfo['ip'],ratinfo['port'],ratinfo['ratname'],ratinfo['type']),topic)
    for ratinfo in p2pcheck():
        print json.dumps(ratinfo,indent=2)
        # mongodb.insert(mongo_formatter(ratinfo['ip'],ratinfo['port'],ratinfo['ratname'],ratinfo['type']))
        # pushdata(kafkasender,kafka_formatter(ratinfo['ip'],ratinfo['port'],ratinfo['ratname'],ratinfo['type'],"udp"),topic)

if __name__ == "__main__":
    main()
