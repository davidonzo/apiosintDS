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
        self.hashlookup = False

        ### !!! ### o_O
        self.entitype = ['url', 'ip', 'domain', 'hash'] #Supported Entities type
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
                        "hash": {
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

    def goodResult(self, item, entype, relatedByHash=False, hashes=False):
        ret = {}
        ret["item"] = item
        ret["response"] = True
        ret["response_text"] = "Item found in "+self.lists["lookup"][entype]["file"]+" list"
        if entype in ['ip', 'domain']:
            ret["related_urls"] = self.parseRelatedUrl(item)
        elif entype == 'url':
            searchUrlHash = self.searchUrlHash(item)
            ret["hashes"] = searchUrlHash
            getItem = urlparse(item)
            ret["related_urls"] = self.parseRelatedUrl(getItem.hostname, item)
        elif entype == 'hash':
            ret["hashes"] = hashes
            ret["related_urls"] = relatedByHash
        else:
            pass
        return ret

    def badResult(self, item, entype):
        ret = {}
        ret["item"] = item
        ret["response"] = False
        ret["response_text"] = "Item not found"
        ret["related_urls"] = ""
        return ret

    def parseRelatedUrl(self, item, ItemURL=False):
        relatedURLs = []
        resUrls = self.lists["lookup"]["url"]["items"]
        for lineurl in resUrls:
            ParseURL = urlparse(lineurl)
            if (ParseURL.hostname == item) and (lineurl != ItemURL):
            
                relhashes = self.searchUrlHash(lineurl)
                
                reldict = {'url': lineurl, 'hashes': relhashes}
                relatedURLs.append(reldict)
        return relatedURLs

    def searchUrlHash(self, item):
        ret = False
        for obj in self.lists["lookup"]["hash"]["items"]:
            if item in self.lists["lookup"]["hash"]["items"][obj]["url"]:
                return {"md5": self.lists["lookup"]["hash"]["items"][obj]["md5"], "sha1": self.lists["lookup"]["hash"]["items"][obj]["sha1"], "sha256": self.lists["lookup"]["hash"]["items"][obj]["sha256"]}
         
        return ret  
            
    def searchHash(self, item):
        hashtype_dict = {32: "md5", 40: "sha1", 64: "sha256"}
        hashlen = len(item)
        hashtype = hashtype_dict[hashlen]
        for obj in self.lists["lookup"]["hash"]["items"]:
            if item in self.lists["lookup"]["hash"]["items"][obj][hashtype]:
                hashes = {"md5": self.lists["lookup"]["hash"]["items"][obj]["md5"], "sha1": self.lists["lookup"]["hash"]["items"][obj]["sha1"], "sha256": self.lists["lookup"]["hash"]["items"][obj]["sha256"]}
                self.output["hash"]["items"].append(self.goodResult(item, "hash", self.lists["lookup"]["hash"]["items"][obj]["url"], hashes))
                self.output["hash"]["statistics"]["itemFound"] +=1
                break
                
    def ExecSearch(self):
        for entype in self.entitype:
            if len(self.lists["input"]["entities"][entype]) > 0:
                self.output[entype]["list"]["date"] = self.lists["lookup"][entype]["date"]
                self.output[entype]["list"]["url"] = self.lists["lookup"][entype]["url"]
                self.output[entype]["list"]["file"] = self.lists["lookup"][entype]["file"]
                
                for item in self.lists["input"]["entities"][entype]:
                    if entype == "hash":
                        self.searchHash(item)
                    else:
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
