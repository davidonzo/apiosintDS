import sys
import os
import tempfile
import requests
import validators
import logging
import json
from datetime import datetime
import pytz

italyTZ = pytz.timezone("Europe/Rome")
logging.basicConfig(format='%(levelname)s: %(message)s')

class listutils():
    def __init__(self, item, listfile, cache, cachedir, clearcache):
        self.item = item
        self.listfile = listfile
        self.urls = {"master_url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest",
                     "slave_url": "https://osint.digitalside.it/Threat-Intel/lists/latest"}
        self.cache = cache
        if isinstance(cachedir, str):
            self.cachedir = cachedir+"/"
        else:
            self.cachedir = False
        self.clearcache = clearcache

        ### !!! ### o_O
        self.template = {"url": [], "ip": [], "domain": []}
        self.items = self.getItems()
        self.entities = dict(self.getEntities())
        self.checkdate = italyTZ.localize(datetime.strptime(datetime.today().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S'))
        self.cached = dict(self.getCache())

    def getItems(self):
        if self.item is not None:
            self.items = []
            self.items.append(self.item)
        elif self.listfile is not None:
            self.items = self.listfile
        return self.items

    def getEntities(self):
        counter = 0
        for line in self.items:
            if validators.url(line):
                counter += 1
                self.template["url"].append(line)
            elif validators.ipv4(line):
                counter +=1
                self.template["ip"].append(line)
            elif validators.domain(line):
                counter +=1
                self.template["domain"].append(line)
            else:
                logging.warning("{} is not a valid IPv4/domain/url. REMOVED!.".format(line))
        if counter == 0:
            logging.error("No valid elements detected, sorry! Supported entities are IPv4/Domain/URL.")
            exit(1)
        ret = {}
        ret["entities"] = self.template
        ret["centities"] = {"url": len(self.template["url"]), "ip": len(self.template["ip"]), "domain": len(self.template["domain"])}
        return ret

    def getListDate(self, context):
        return italyTZ.localize(datetime.strptime(context[9][16:35], '%Y-%m-%d %H:%M:%S'))

    def getListItems(self, context):
        return context[11:]

    def getCache(self): #Mmhhh, not a good method at all, but works. Added to TODO list for early refactor. 2019-10-12
        cached = {}
        for entity in self.entities["centities"]:
            cached[entity] = {}
            cached[entity]["file"] = "latest"+entity+"s.txt"
            if (self.entities["centities"][entity] == 0) and (entity in ["ip", "domain"]):
                pass
            else:
                if self.cache:
                    cachedfile = self.cachedir+cached[entity]["file"]
                    if os.path.exists(cachedfile):
                        if self.clearcache:
                            dwlist = self.downloadLists(entity)
                            cached[entity]["date"] = self.getListDate(dwlist["text"])
                            cached[entity]["items"] = self.getListItems(dwlist["text"])
                            cached[entity]["url"] = dwlist["url"]
                        else:
                            dwlist = [line.rstrip('\n') for line in open(cachedfile)]
                            listdate = self.getListDate(dwlist)
                            listitems = self.getListItems(dwlist)
                            diffdate = ((self.checkdate-listdate).total_seconds())/3600
                            if ((diffdate) < 4) and (len(listitems) > 0):
                                cached[entity]["date"] = listdate
                                cached[entity]["items"] = listitems
                                cached[entity]["url"] = "Loaded from cache '"+cachedfile+"'"
                            else:
                                dwlist = self.downloadLists(entity)
                                cached[entity]["date"] = self.getListDate(dwlist["text"])
                                cached[entity]["items"] = self.getListItems(dwlist["text"])
                                cached[entity]["url"] = dwlist["url"]
                    else:
                        dwlist = self.downloadLists(entity)
                        cached[entity]["date"] = self.getListDate(dwlist["text"])
                        cached[entity]["items"] = self.getListItems(dwlist["text"])
                        cached[entity]["url"] = dwlist["url"]
                else:
                    dwlist = self.downloadLists(entity)
                    cached[entity]["date"] = self.getListDate(dwlist["text"])
                    cached[entity]["items"] = self.getListItems(dwlist["text"])
                    cached[entity]["url"] = dwlist["url"]
                cached[entity]["date"] = str(cached[entity]["date"])
        return cached

    def saveCache(self, entity, content):
        try:
            cachefile = open(self.cachedir+"latest"+entity+"s.txt", "w")
            cachefile.write(content)
            cachefile.close()
        except IOError as e:
            logging.error(e)
            logging.error("Unable save list! Make sure you have write permission on file "+self.cachedir+"latest"+entity+"s.txt.")
            logging.error("Retry without -c, --cache option.")
            exit(1)

    def downloadLists(self, entity):
        ret = {}
        ret["url"] = self.urls['master_url']+entity+'s.txt'
        r = requests.get(ret["url"])
        if r.status_code != 200:
            ret["url"] = self.urls['slave_url']+entity+'s.txt'
            logging.warning("Error downloading lastes{}.txt from GitHub repository.".format(entity))
            logging.warning("Returned HTTP status code is {}:".format(r.status_code))
            logging.warning("Try downloading file from osint.digitalside.it")
            r = requests.get(ret["url"])
            if r.status_code != 200:
                logging.warning("Error downloading lastes{}s.txt both from GitHub repository and OSINT.digitalside.it".format(entity))
                logging.warning("Returned HTTP status code is {}:".format(r.status_code))
                logging.error(self.status_error(entity))
                exit(1) 
            return 1
        text = r.text
        if len(text) == 0:
            logging.error("The downloaded list seems to be empty!\n")
            logging.error(self.status_error(entity))
            exit(1)
        return_text = text.split('\n')
        if len(return_text[11:]) == 0: #just because I'm a very paranoid man, but same time a lazy one ^_^'''
            logging.error("The downloaded list seems to be empty!\n")
            logging.error(self.status_error(entity))
            exit(1)
        else:
            ret["text"] = return_text
        if self.cache:
            self.saveCache(entity, text)
        return ret

    def status_error(self, entity):
        error="Check the following urls using your prefered browser:\n"
        error+="- https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest"+entity+".txt\n"
        error+="- https://osint.digitalside.it/Threat-Intel/lists/latest"+entity+".txt\n"
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

    def prepareLists(self):
        ret = {}
        ret["input"] = self.entities
        ret["lookup"] = self.cached
        return ret
