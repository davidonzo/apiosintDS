import sys
import os
import requests
import validators
import json
from datetime import datetime
import time
import re
from stix2 import parse
import pytz

italyTZ = pytz.timezone("Europe/Rome")

class stixreport():
    def __init__(self, item, cache, cachedir, clearcache, cachetimeout, localdirectory, logger):
        
        self.logger = logger
        self.item = item
        self.report = item+".json"
        self.urls = {"master_url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/stix2/",
                     "slave_url": "https://osint.digitalside.it/Threat-Intel/stix2/"}
        self.cache = cache
        if isinstance(cachedir, str):
            self.cachedir = cachedir+"/"
        else:
            self.cachedir = False
        self.clearcache = clearcache
        self.cachetimeout = cachetimeout
        if localdirectory != False:
            self.localdirectory = localdirectory if localdirectory[:len(localdirectory)] == os.sep else localdirectory+os.sep
        else:
            self.localdirectory = localdirectory

        self.checkdate = italyTZ.localize(datetime.strptime(datetime.today().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S'))
        self.getStix = self.getCache()


    def getListDate(self, reportContent):
        ret = False
        for obj in reportContent["objects"]:
            if obj["type"] == "report":
                ret = obj["published"]
        #datetime.strptime(str(fromdate), '%Y-%m-%d %H:%M:%S+00:00')
        return italyTZ.localize(datetime.strptime(ret, '%Y-%m-%dT%H:%M:%SZ'))
    
    def getCache(self):
        dwreport = False
        if self.cache:
            cachedfile = self.cachedir+self.report
            if os.path.exists(cachedfile):
                if self.clearcache:
                    dwreport = json.loads(self.downloadReport())
                else:
                    cacheHandler = open(cachedfile, 'r')
                    content = cacheHandler.read()
                    cacheHandler.close()
                    dwreport = json.loads(content)
                
                if self.cachetimeout > 0:
                    reportDate = self.getListDate(dwreport)
                    diffdate = ((self.checkdate-reportDate).total_seconds())/3600
                
                    if diffdate < self.cachetimeout:
                        logger.info("Report "+self.report+" loaded from cache")
                    else:
                        dwreport = self.downloadReport()
                else:
                    dwreport = self.downloadReport()
            else:
                dwreport = self.downloadReport()
        else:
            dwreport = self.downloadReport()
        return dwreport

    def saveCache(self, entity, content):
        try:
            cachefile = open(self.cachedir+self.report, "w")
            cachefile.write(content)
            cachefile.close()
        except IOError as e:
            self.logger.error(e)
            self.logger.error("Unable save list! Make sure you have write permission on file "+self.cachedir+self.report)
            self.logger.error("Retry without -c, --cache option.")
            exit(1)

    def openLocalReport(self, reportfile):
        ret = False
        thereportfile = self.localdirectory+"stix2/"+reportfile
        if os.path.isfile(thereportfile):
            try:
                ret = open(thereportfile).read()
            except ValueError as e:
                self.logger.error(e)
                exit(1)
        return ret
    
    def downloadReport(self):
        ret = False
        
        if self.localdirectory:
            stixreport = self.openLocalReport(self.report)
        else:
            reportURL = self.urls['master_url']+self.report
            r = requests.get(reportURL)
            if r.status_code != 200:
                reportURL = self.urls['slave_url']+self.report
                self.logger.warning("Error downloading {} from GitHub repository.".format(self.report))
                self.logger.warning("Returned HTTP status code is {}:".format(r.status_code))
                self.logger.warning("Try downloading file from osint.digitalside.it")
                r = requests.get(ret["url"])
                if r.status_code != 200:
                    self.logger.warning("Error downloading {} both from GitHub repository and OSINT.digitalside.it".format(self.report))
                    self.logger.warning("Returned HTTP status code is {}:".format(r.status_code))
                    self.logger.error(self.status_error(self.report))
                    return ret
                return ret
            
            stixreport = r.text
        if len(stixreport) == 0:
            self.logger.error("The downloaded list seems to be empty!\n")
            if self.localdirectory == False:
                self.logger.error(self.status_error(self.report))
            return ret
        
        if self.cache:
            self.saveCache(self, stixreport)
        return stixreport

    def status_error(self):
        error="Check the following urls using your prefered browser:\n"
        error+="- https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/stix2/"+self.report+"\n"
        error+="- https://osint.digitalside.it/Threat-Intel/stix2/"+self.report+"\n"
        error+="\n"
        error+="Are you able to view the desired IoC list? If not, please, report this opening an issue on Threat-Intel GitHub repository:\n"
        error+="- https://github.com/davidonzo/Threat-Intel/issues\n"
        error+="\n"
        error+="Aren't you familiar with GitHub? No worries. You can send a PGP signed and encrypted email to info@digitalside.it\n"
        error+="PGP key ID: 30B31BDA\n"
        error+="PGP fingerprint: 0B4C F801 E8FF E9A3 A602  D2C7 9C36 93B2 30B3 1BDA\n"
        error+="\n"
        error+="Aren't you familiar with PGP? Be worried... maybe you should not use this script ;-)\n"
        return error
        
    def releaseReport(self):
        if self.getStix == False:
            return False
        return parse(self.getStix)
        
    def parseReport(self):
        ret = False
        
        report = self.releaseReport()

        if report != False:
            ret = {}
            ret["observed_time_frame"] = False
            ret["indicators_count"] = {"hashes": 0, "urls": 0, "domains": 0, "ipv4": 0}
            
            for obj in report.objects:
                if obj.type == "marking-definition":
                    ret["tlp"] = obj.definition.tlp
                if obj.type == "malware":
                    ret["first_observed"] = obj.first_seen.strftime('%Y-%m-%d %H:%M:%S')
                    ret["last_observed"] = obj.last_seen.strftime('%Y-%m-%d %H:%M:%S')
                    if obj.first_seen != obj.last_seen:
                        ret["observed_time_frame"] = self.calcTimeFrame(obj.first_seen, obj.last_seen)
                    ret["virus_total"] = self.getVTReport(obj)
                if obj.type == "observed-data":
                    ret["number_observed"] = obj.number_observed
                if obj.type == "file":
                    ret["filename"] = obj.name
                    ret["filesize"] = obj.size
                    ret["mime_type"] = obj.mime_type
                if obj.type == "indicator":
                    searchPattern = str(obj.pattern)[:10]
                    if searchPattern == "[file:hash":
                        ret["indicators_count"]["hashes"] +=1
                    elif searchPattern == "[url:value":
                        ret["indicators_count"]["urls"] +=1
                    elif searchPattern == "[domain-na":
                        ret["indicators_count"]["domains"] +=1
                    elif searchPattern == "[ipv4-addr":
                        ret["indicators_count"]["ipv4"] +=1
        return ret
    
    def getVTReport(self, obj):
        ret = False
        if obj.external_references:
            for url in obj.external_references:
                if str(url.description)[:11] == "Virus Total":
                    ret = {"vt_detection_ratio": url.description[28:], "vt_report": url.url}
        return ret
    
    def calcTimeFrame(self, fromdate, todate):
        ret = False
        timedeltaobj = (datetime.strptime(str(todate), '%Y-%m-%d %H:%M:%S+00:00') - datetime.strptime(str(fromdate), '%Y-%m-%d %H:%M:%S+00:00'))

        if timedeltaobj.total_seconds() > 0:
            ret = str(timedeltaobj)
        return ret
