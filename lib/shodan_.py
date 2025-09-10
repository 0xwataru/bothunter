#!/usr/bin/env python
# -*- coding: utf-8 -*-


import shodan
import time
import math
import datetime
import json
import logging
# from ConfigParser import ConfigParser
from lib.utils.config import ConfigFileParser

def init_shodan():
    API_KEY = ConfigFileParser().ShodanApikey()
    api = shodan.Shodan(API_KEY)
    return api

def shodan_host(api,ip):
    try:
        host = api.host(ip)
    except shodan.APIError, e:
        logging.error('Error: %s' % e)
    return host['data']

def shodan_scan(api,ips):
    try:
        receive = api.scan(ips)
    except shodan.APIError, e:
        logging.error('Error: %s' % e)
    return receive


def shodan_search(api,query):
    ratinfo = []
    page_count = {}
    try:
        page_count = api.search(query, page=1, limit=None, offset=None, facets=None, minify=True)
        onepage=savefile(page_count)
        ratinfo.extend(onepage)
    except shodan.APIError, e:
        logging.error('Error: %s' % e)
        return
    page =int(math.ceil(page_count['total']/100.0))
    for i in range(2,page+1):
        try:
            search = api.search(query, page=i, limit=None, offset=None, facets=None, minify=True)
        except shodan.APIError, e:
            logging.error('Error: %s' % e)
        nextpage = savefile(search)
        ratinfo.extend(nextpage)
    return ratinfo

def gettype(ratname):
    if ratname.lower() in ['zeroaccess']:#zeroaccess
        return 'p2p botnet'
    return 'c2 botnet'

def savefile(page_result):
    ratinfo =[]
    for item in page_result['matches']:
        ratname = (item['product']).split(' ')[0].lower()
        ratinfo.append({"ratname":ratname,"ip": item['ip_str'], "port": item['port'],'type':gettype(ratname)})
    return ratinfo



if __name__ == '__main__':
    result = shodan_search('category:malware')
    print json.dumps(result,indent=2)


