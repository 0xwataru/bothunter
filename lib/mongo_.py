#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymongo import MongoClient
import logging
import datetime
from lib.utils.config import ConfigFileParser

def init_mongodb():
    IP = ConfigFileParser().MongoServerIp()
    PORT = ConfigFileParser().MongoServerPort()
    DB = ConfigFileParser().MongoServerDb()
    COLLECTION = ConfigFileParser().MongoServerCollection()
    try:
        db_conn = MongoClient(IP, PORT)
        na_db = getattr(db_conn, DB)
        na_collection = na_db[COLLECTION]#na_db.Result
    except:
        logging.error('mongo init falied!')
        pass
    logging.info('mongo init successful!')
    return na_collection



def mongo_formatter(ip,port,ratname,rattype):
    vulinfo = {"RATfinderName": ratname, "RAT_level": 'high',
               "RAT_type": rattype}
    w_vul = {"task_id": 'shodan_get', "ip": ip, "port": port,
             "RAT_info": vulinfo, "info": '', "time": datetime.datetime.now(),
             "task_date": '2018-05-11', "threat_level": "high", 'tags': ['c2', ratname]}
    return w_vul