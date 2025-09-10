#!/usr/bin/env python
# -*- coding: utf-8 -*-


import ConfigParser
from lib.core.data import paths, logger
# from lib.core.common import getSafeExString


class ConfigFileParser:
    @staticmethod
    def _get_option(section, option):
        try:
            cf = ConfigParser.ConfigParser()
            cf.read(paths.CONFIG_PATH)
            return cf.get(section=section, option=option)
        except ConfigParser.NoOptionError, e:
            logger.warning('Missing essential options, please check your config-file.')
            # logger.error(getSafeExString(e))
            logger.error((e))
            return ''

    def MongoServerIp(self):
        return self._get_option('mongo', 'ip')

    def MongoServerPort(self):
        return self._get_option('mongo', 'port')

    def MongoServerDb(self):
        return self._get_option('mongo', 'db')

    def MongoServerCollection(self):
        return self._get_option('mongo', 'collection')

    def KafkaCluster(self):
        return self._get_option('kafka', 'bootstrap_servers')

    def KafkaTopic(self):
        return self._get_option('kafka', 'topic')

    def ShodanApikey(self):
        return self._get_option('shodan', 'apikey')

    def P2pEntPointFile(self):
        return self._get_option('p2p', 'file')

    def P2pEntPointMongdb(self):
        return self._get_option('p2p', 'mongo')

    def DefaultP2pEntPoint(self):
        return self._get_option('p2p', 'default_ent')

    def ZoomEyeEmail(self):
        return self._get_option('zoomeye', 'email')

    def ZoomEyePassword(self):
        return self._get_option('zoomeye', 'password')

    def BingApikey(self):
        return self._get_option('bing', 'apikey')

    def CloudEyeApikey(self):
        return self._get_option('cloudeye', 'apikey')

    def ColudEyePersonaldomain(self):
        return self._get_option('cloudeye', 'personaldomain')

    def GoogleProxy(self):
        return self._get_option('google', 'proxy')

    def GoogleDeveloperKey(self):
        return self._get_option('google', 'developer_key')

    def GoogleEngine(self):
        return self._get_option('google', 'search_engine')

    def FofaEmail(self):
        return self._get_option('fofa','email')

    def FofaKey(self):
        return self._get_option('fofa','apikey')
