import sys
import os
import logging
import json
from datetime import datetime
import pytz
italyTZ = pytz.timezone("Europe/Rome")
logging.basicConfig(format='%(levelname)s: %(message)s')
try:
    from urllib.parse import urlparse
except ImportError as ierror:
    logging.error(ierror)
    logging.error("To run this script you need to install the \"urllib\" module")
    logging.error("Try typing: \"pip3 install urllib3\"")
    exit(0)

class dosearch():
    def __init__(self, lists, verbose):
        self.lists = lists
        self.verbose = verbose

        ### !!! ### o_O
        self.entitype = ['url', 'ip', 'domain'] #Supported Entities type
        self.output = {
                        "url": {
                                    "items": [],
                                    "statistics": {
                                                "itemFound": 0,
                                                "itemSubmitted": 0
                                    },
                                    "list": {
                                                "file": "undefined",
                                                "date": "undefined",
                                                "url": "undefined"
                                    }
                               },
                        "ip": {
                                    "items": [],
                                    "statistics": {
                                                "itemFound": 0,
                                                "itemSubmitted": 0
                                    },
                                    "list": {
                                                "file": "undefined",
                                                "date": "undefined",
                                                "url": "undefined"
                                    }
                               },
                        "domain": {
                                    "items": [],
                                    "statistics": {
                                                "itemFound": 0,
                                                "itemSubmitted": 0
                                    },
                                    "list": {
                                                "file": "undefined",
                                                "date": "undefined",
                                                "url": "undefined"
                                    }
                               },
                      }
        self.getResults = self.ExecSearch()

    def goodResult(self, item, entype):
        ret = {}
        ret["item"] = item
        ret["response"] = True
        ret["response_text"] = "Item found in "+self.lists["lookup"][entype]["file"]+" list"
        if entype != 'url':
            ret["related_urls"] = self.parseRelatedUrl(item)
        else:
            getItem = urlparse(item)
            ret["related_urls"] = self.parseRelatedUrl(getItem.hostname)
            ret["related_urls"].remove(item)
        return ret

    def badResult(self, item, entype):
        ret = {}
        ret["item"] = item
        ret["response"] = False
        ret["response_text"] = "Item not found"
        ret["related_urls"] = []
        return ret

    def parseRelatedUrl(self, item):
        relatedURLs = []
        resUrls = self.lists["lookup"]["url"]["items"]
        for lineurl in resUrls:
            ParseURL = urlparse(lineurl)
            if ParseURL.hostname == item:
                relatedURLs.append(lineurl)
        return relatedURLs

    def ExecSearch(self):
        for entype in self.entitype:
            if len(self.lists["input"]["entities"][entype]) > 0:
                self.output[entype]["list"]["date"] = self.lists["lookup"][entype]["date"]
                self.output[entype]["list"]["url"] = self.lists["lookup"][entype]["url"]
                self.output[entype]["list"]["file"] = self.lists["lookup"][entype]["file"]
                for item in self.lists["input"]["entities"][entype]:
                    if item in self.lists["lookup"][entype]["items"]:
                        self.output[entype]["items"].append(self.goodResult(item, entype))
                        self.output[entype]["statistics"]["itemFound"] +=1
                    else:
                        if self.verbose:
                            self.output[entype]["items"].append(self.badResult(item, entype))
                self.output[entype]["statistics"]["itemSubmitted"] = len(self.lists["input"]["entities"][entype])
            else:
                del self.output[entype]
        return self.output

    def prepareResults(self):
        return self.output
