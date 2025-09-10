#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
from kafka import KafkaProducer
import logging
# from ConfigParser import ConfigParser
# config = ConfigParser()
# # config.read('../config.ini')
# config.read('config.ini')
from lib.utils.config import ConfigFileParser
#
# bootstrap_servers = json.loads(config.get('kafka', 'bootstrap_servers'))
# topic = config.get('kafka', 'topic')

def init_kafka():
    bootstrap_servers = json.loads(ConfigFileParser().KafkaCluster())
    topic = ConfigFileParser().KafkaTopic()
    producer = KafkaProducer(bootstrap_servers=bootstrap_servers)
    return  producer,topic

def pushdata(producer,data,topic):
    try:
        producer.send(topic,json.dumps(data))
    except Exception,e:
        # print "kafka send is error:%s"%e
        logging.error("kafka sender error:%s"%e)
    logging.info('kafka send data successful!')

def kafka_formatter(ip,port,ratname,rattype,protocol):
    kafka_result = {"ioc": ip, "port": port, 'type': 'ip',
                    'tags': [rattype.split(' ')[0].lower(), ratname],
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                    "protocol":protocol,
                    'provider': 'hansight.com', 'confidence': 80, 'threat_level': 'high', 'producer': 'malhunter'}
    return kafka_result
