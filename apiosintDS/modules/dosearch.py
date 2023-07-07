import sys
import os
import json
from datetime import datetime
import pytz
from urllib.parse import urlparse
from apiosintDS.modules.stixreport import stixreport
italyTZ = pytz.timezone("Europe/Rome")


class dosearch():
    def __init__(self, lists, verbose, stix, cache, cachedirectory, clearcache, cachetimeout, localdirectory, logger):
        self.logger = logger
        self.lists = lists
        self.verbose = verbose
        self.stix = stix
        self.cache = cache
        self.cachedirectory = cachedirectory
        self.clearcache = clearcache
        self.cachetimeout = cachetimeout
        if localdirectory != False:
            self.localdirectory = localdirectory if localdirectory[(len(localdirectory)-1):] == os.sep else localdirectory+os.sep
        else:
            self.localdirectory = localdirectory
        self.osintDS = "https://osint.digitalside.it"

        ### !!! ### o_O
        self.generalStats = self.lists["input"]["GeneralStats"]
        self.entitype = ['url', 'ip', 'domain', 'hash'] #Supported Entities type
        self.output = {
                        "url": {
                                    "items": [],
                                    "statistics": {
                                                "itemsFound": 0,
                                                "itemsSubmitted": 0
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
                                                "itemsFound": 0,
                                                "itemsSubmitted": 0
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
                                                "itemsFound": 0,
                                                "itemsSubmitted": 0
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
                                                "itemsFound": 0,
                                                "itemsSubmitted": 0
                                    },
                                    "list": {
                                                "file": "undefined",
                                                "date": "undefined",
                                                "url": "undefined"
                                    }
                               }, 
                         "generalstatistics": self.lists["input"]["GeneralStats"],
                         "apiosintDSversion": self.lists["input"]["apiosintDSversion"],
                      }
        
        self.getResults = self.ExecSearch()

    def goodResult(self, item, entype, relatedByHash=False, hashes=False):
        ret = {}
        ret["item"] = item
        ret["response"] = True
        ret["response_text"] = "Item found in "+self.lists["lookup"][entype]["file"]+" list"
        if entype in ['ip', 'domain']:
            ret["related_urls"] = self.parseRelatedUrl(item)
            if(len(ret["related_urls"])>0):
                for relatedurls in ret["related_urls"]:
                    onlineReports = self.searchMISPSTIXCSV(relatedurls["url"], "url")
                    relatedurls["online_reports"] = onlineReports
        elif entype == 'url':
            searchUrlHash = self.searchUrlHash(item)
            ret["hashes"] = searchUrlHash
            ret["online_reports"] = self.searchMISPSTIXCSV(item, entype)
            getItem = urlparse(item)
            ret["related_urls"] = self.parseRelatedUrl(getItem.hostname, item)
            if(len(ret["related_urls"])>0):
                for relatedurls in ret["related_urls"]:
                    if relatedurls["hashes"]["md5"] != ret["hashes"]["md5"]:
                        onlineReports = self.searchMISPSTIXCSV(relatedurls["url"], "url")
                        relatedurls["online_reports"] = onlineReports
        elif entype == 'hash':
            ret["hashes"] = hashes
            ret["online_reports"] = self.searchMISPSTIXCSV(item, entype)
            ret["related_urls"] = relatedByHash
        else:
            pass
        return ret

    def badResult(self, item, entype):
        ret = {}
        ret["item"] = item
        ret["response"] = False
        ret["response_text"] = "Item not found"
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
        #ret = False
        for obj in self.lists["lookup"]["hash"]["items"]:
            if item in self.lists["lookup"]["hash"]["items"][obj]["url"]:
                return {"md5": self.lists["lookup"]["hash"]["items"][obj]["md5"], "sha1": self.lists["lookup"]["hash"]["items"][obj]["sha1"], "sha256": self.lists["lookup"]["hash"]["items"][obj]["sha256"]}
         
        return ret
        
    def searchMISPSTIXCSV(self, item, entype):
        ret = False
        for key, obj in self.lists["lookup"]["hash"]["items"].items():
            if entype == "hash":
                hashtype = self.hashtype(item)
            elif entype == "url":
                hashtype = "url"
                
            if item in self.lists["lookup"]["hash"]["items"][key][hashtype]:
                if self.localdirectory:
                    ret = {}
                    if os.path.isfile(self.localdirectory+"digitalside-misp-feed/"+key+".json"):
                        ret["MISP_EVENT"] = self.localdirectory+"digitalside-misp-feed/"+key+".json"
                    if os.path.isfile(self.localdirectory+"csv/"+key+".csv"):
                        ret["MISP_CSV"] = self.localdirectory+"csv/"+key+".csv"
                    ret["OSINTDS_REPORT"] = self.osintDS+"/report/"+self.lists["lookup"]["hash"]["items"][key]["md5"]+".html"
                    if os.path.isfile(self.localdirectory+"stix2/"+self.lists["lookup"]["hash"]["items"][key]["md5"]+".json"):
                        ret["STIX"] = self.localdirectory+"stix2/"+self.lists["lookup"]["hash"]["items"][key]["md5"]+".json"
                else:
                    ret = {
                            "MISP_EVENT": self.osintDS+"/Threat-Intel/digitalside-misp-feed/"+key+".json",
                            "MISP_CSV": self.osintDS+"/Threat-Intel/csv/"+key+".csv",
                            "OSINTDS_REPORT": self.osintDS+"/report/"+self.lists["lookup"]["hash"]["items"][key]["md5"]+".html",
                            "STIX": self.osintDS+"/Threat-Intel/stix2/"+self.lists["lookup"]["hash"]["items"][key]["md5"]+".json"
                        }
                        
                if self.stix:
                    ret["STIXDETAILS"] = stixreport(self.lists["lookup"]["hash"]["items"][key]["md5"], self.cache, self.cachedirectory, self.clearcache, self.cachetimeout, self.localdirectory, self.logger).parseReport()
                    
                    
            
                   
        return ret
            
    def hashtype(self, item):
        ret = False
        hashtype_dict = {32: "md5", 40: "sha1", 64: "sha256"}
        hashlen = len(item)
        ret = hashtype_dict[hashlen]
        
        return ret
    
    def searchHash(self, item):
        hashtype = self.hashtype(item)
        hashes = False
        for obj in self.lists["lookup"]["hash"]["items"]:
            if item in self.lists["lookup"]["hash"]["items"][obj][hashtype]:
                hashes = {"md5": self.lists["lookup"]["hash"]["items"][obj]["md5"], "sha1": self.lists["lookup"]["hash"]["items"][obj]["sha1"], "sha256": self.lists["lookup"]["hash"]["items"][obj]["sha256"]}
                self.output["hash"]["items"].append(self.goodResult(item, "hash", self.lists["lookup"]["hash"]["items"][obj]["url"], hashes))
                self.output["hash"]["statistics"]["itemsFound"] +=1
                self.generalStats["itemsFound"] +=1
                self.generalStats["hashfound"] +=1
                break
        
        if self.verbose and hashes == False:
            self.output["hash"]["items"].append(self.badResult(item, "hash"))
        
        return

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
                            self.output[entype]["statistics"]["itemsFound"] +=1
                            self.generalStats["itemsFound"] +=1
                            self.generalStats[entype+"found"] +=1
                            
                        else:
                            if self.verbose:
                                self.output[entype]["items"].append(self.badResult(item, entype))
                self.output[entype]["statistics"]["itemsSubmitted"] = len(self.lists["input"]["entities"][entype])
                self.generalStats["itemsSubmitted"] = self.generalStats["itemsSubmitted"]+self.output[entype]["statistics"]["itemsSubmitted"]
            else:
                del self.output[entype]
        return self.output

    def prepareResults(self):
        return self.output
