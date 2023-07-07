import sys
import os
import requests
import validators
import json
from datetime import datetime
from apiosintDS.modules.scriptinfo import scriptinfo
import re
import pytz

italyTZ = pytz.timezone("Europe/Rome")

class listutils():
    def __init__(self, item, listfile, cache, cachedir, clearcache, cachetimeout, localdirectory, logger):
        self.logger = logger
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
        self.cachetimeout = cachetimeout
        if localdirectory != False:
            self.localdirectory = localdirectory if localdirectory[:len(localdirectory)] == os.sep else localdirectory+os.sep
        else:
            self.localdirectory = localdirectory
        self.version = scriptinfo["scriptname"]+" v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]
        
        ### !!! ### o_O
        self.template = {"url": [], "ip": [], "domain": [], "hash": []}
        self.invaliditems = 0
        self.duplicateditems = 0
        self.items = self.getItems()
        self.entities = dict(self.getEntities())
        self.checkdate = italyTZ.localize(datetime.strptime(datetime.today().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S'))
        self.cached = dict(self.getCache())
        
        self.entitiesStats = {"url": len(self.template["url"]), 
                              "ip": len(self.template["ip"]), 
                              "domain": len(self.template["domain"]), 
                              "hash": len(self.template["hash"]),
                              "invalid": self.invaliditems,
                              "duplicates": self.duplicateditems,
                              "itemsFound": 0,
                              "itemsSubmitted": 0,
                              "urlfound": 0,
                              "ipfound": 0,
                              "domainfound": 0,
                              "hashfound": 0,
                              }

    def getItems(self):
        if self.item is not None:
            self.items = []
            self.items.append(self.item)
        elif self.listfile is not None:
            self.items = list(dict.fromkeys(self.listfile))
            duplicate = len(self.listfile) - len(self.items)
            if duplicate > 0:
                self.duplicateditems = duplicate
                self.logger.warning(f'Removed {duplicate} duplicate(s) from IoCs lists to check')
        return self.items

    def validatehash(self, hstring):
        ret = False
        digits = len(hstring)
        if digits in [32, 40, 64]:
            try:
                ret = re.match(r'^[0-9a-f]{'+str(digits)+'}$', hstring).group(0)
            except:
                self.logger.info("Invalid hash detected: failed validation for ["+hstring+"]")
        else:
            self.logger.info("Invalid hash detected: failed lenght check for ["+hstring+" len("+str(digits)+")]")
        return ret

    def getEntities(self):
        counter = 0
        for line in self.items:
            line = line.strip()
            if validators.url(line):
                counter += 1
                self.template["url"].append(line)
            elif validators.ipv4(line):
                counter +=1
                self.template["ip"].append(line)
            elif validators.domain(line):
                counter +=1
                self.template["domain"].append(line)
            elif self.validatehash(line):
                counter +=1
                self.template["hash"].append(line)
            elif len(line) == 0:
            	 self.logger.warning("Empty line ignored!")
            else:
                self.invaliditems +=1
                self.logger.warning("{} is not a valid IPv4/domain/url/hash. REMOVED!.".format(line))
        if counter == 0:
            self.logger.error("No valid elements detected, sorry! Supported entities are IPv4/Domain/URL/Hash ['MD5', 'SHA1', 'SHA256'].")
            exit(1)
        ret = {}
        ret["entities"] = self.template
        ret["centities"] = {"url": len(self.template["url"]), "ip": len(self.template["ip"]), "domain": len(self.template["domain"]), "hash": len(self.template["hash"])}
        return ret

    def getListDate(self, context, hashes=False):
        if hashes:
            context = json.loads(context)
            listdate = context["generatedAt"]
        else:
            listdate = context[9][16:35]
        return italyTZ.localize(datetime.strptime(listdate, '%Y-%m-%d %H:%M:%S'))

    def getListItems(self, context, hashes=False):
        if hashes:
            context = json.loads(context)
            listitems = context["lookup"]
        else:
            listitems = context[11:]
        return listitems

    def getCache(self): #Mmhhh, not a good method at all, but works. Added to TODO list for early refactor. 2019-10-12
        cached = {}
        for entity in self.entities["centities"]:
            getHash = (True if entity == "hash" else False)
            cached[entity] = {}
            cached[entity]["file"] = "latest"+entity+"es.json" if entity == "hash" else "latest"+entity+"s.txt"
            if (self.entities["centities"][entity] == 0) and (entity in ["ip", "domain"]):
                pass
            else:
                if self.cache:
                    cachedfile = self.cachedir+cached[entity]["file"]
                    if os.path.exists(cachedfile):
                        if self.clearcache:
                            dwlist = self.downloadLists(entity, getHash)
                            cached[entity]["date"] = self.getListDate(dwlist["text"], getHash)
                            cached[entity]["items"] = self.getListItems(dwlist["text"], getHash)
                            cached[entity]["url"] = dwlist["url"]
                        else:
                            if entity == "hash":
                                cacheHandler = open(cachedfile, 'r')
                                content = cacheHandler.read()
                                cacheHandler.close()
                                dwlist = content
                            else:
                                dwlist = [line.rstrip('\n') for line in open(cachedfile)]
                            
                            listdate = self.getListDate(dwlist, getHash)
                            listitems = self.getListItems(dwlist, getHash)
                                
                            if self.cachetimeout > 0:
                                diffdate = ((self.checkdate-listdate).total_seconds())/3600
                                if ((diffdate) < 4) and (len(listitems) > 0):
                                    cached[entity]["date"] = listdate
                                    cached[entity]["items"] = listitems
                                    cached[entity]["url"] = "Loaded from cache '"+cachedfile+"'"
                                else:
                                    dwlist = self.downloadLists(entity, getHash)
                                    cached[entity]["date"] = self.getListDate(dwlist["text"], getHash)
                                    cached[entity]["items"] = self.getListItems(dwlist["text"], getHash)
                                    cached[entity]["url"] = dwlist["url"]
                            else:
                                dwlist = self.downloadLists(entity, getHash)
                                cached[entity]["date"] = self.getListDate(dwlist["text"], getHash)
                                cached[entity]["items"] = self.getListItems(dwlist["text"], getHash)
                                cached[entity]["url"] = dwlist["url"]
                    else:
                        dwlist = self.downloadLists(entity, getHash)
                        cached[entity]["date"] = self.getListDate(dwlist["text"], getHash)
                        cached[entity]["items"] = self.getListItems(dwlist["text"], getHash)
                        cached[entity]["url"] = dwlist["url"]
                else:
                    dwlist = self.downloadLists(entity, getHash)
                    cached[entity]["date"] = self.getListDate(dwlist["text"], getHash)
                    cached[entity]["items"] = self.getListItems(dwlist["text"], getHash)
                    cached[entity]["url"] = dwlist["url"]
                cached[entity]["date"] = str(cached[entity]["date"])
        return cached

    def saveCache(self, entity, content):
        try:
            file_ext = 'txt'
            if (entity == 'hashe'): 
                file_ext = 'json'
                    
            cachefile = open(self.cachedir+"latest"+entity+"s."+file_ext, "w")
            cachefile.write(content)
            cachefile.close()
        except IOError as e:
            self.logger.error(e)
            self.logger.error("Unable save list! Make sure you have write permission on file "+self.cachedir+"latest"+entity+"s."+file_ext+".")
            self.logger.error("Retry without -c, --cache option.")
            exit(1)

    def openLocalLists(self, listfile):
        ret = False
        thelistfile = self.localdirectory+"lists/"+listfile
        if os.path.isfile(thelistfile):
            try:
                ret = open(thelistfile).read()
                
            except ValueError as e:
                self.logger.error(e)
                exit(1)
        else:
            self.logger.error("File not found: "+listfile)
            exit(1)
        return ret
    
    def downloadLists(self, entity, hashes=False):
        # micro patch for hashes vs hash
        entity = entity+"e" if entity == "hash" else entity
        ret = {}
        
        # New file format for hash entities
        
        file_ext = 'txt'
        if (entity == 'hashe'): 
            file_ext = 'json'
        
        if self.localdirectory:
            text = self.openLocalLists('latest'+entity+'s.'+file_ext)
            ret["url"] = self.localdirectory+'latest'+entity+'s.'+file_ext
        else:
            ret["url"] = self.urls['master_url']+entity+'s.'+file_ext
            r = requests.get(ret["url"])
            if r.status_code != 200:
                ret["url"] = self.urls['slave_url']+entity+'s.'+file_ext
                self.logger.warning("Error downloading lastes{}.{} from GitHub repository.".format(entity, file_ext))
                self.logger.warning("Returned HTTP status code is {}:".format(r.status_code))
                self.logger.warning("Try downloading file from osint.digitalside.it")
                r = requests.get(ret["url"])
                if r.status_code != 200:
                    self.logger.warning("Error downloading lastes{}s.{} both from GitHub repository and OSINT.digitalside.it".format(entity, file_ext))
                    self.logger.warning("Returned HTTP status code is {}:".format(r.status_code))
                    self.logger.error(self.status_error(entity))
                    exit(1) 
                return 1
            text = r.text
        if len(text) == 0:
            self.logger.error("The downloaded list seems to be empty!\n")
            self.logger.error(self.status_error(entity))
            exit(1)
        if hashes:
            return_text = text
        else:
            return_text = text.split('\n')
        if len(return_text[11:]) == 0: #just because I'm a very paranoid man, but same time a lazy one ^_^'''
            self.logger.error("The downloaded list seems to be empty!\n")
            if self.localdirectory == False:
                self.logger.error(self.status_error(entity))
            exit(1)
        else:
            ret["text"] = return_text
        if self.cache:
            self.saveCache(entity, text)
        return ret

    def status_error(self, entity):
        file_ext = 'txt'
        if (entity == 'hashe'): 
            file_ext = 'json'
    
        error="Check the following urls using your prefered browser:\n"
        error+="- https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest"+entity+"."+file_ext+"\n"
        error+="- https://osint.digitalside.it/Threat-Intel/lists/latest"+entity+"."+file_ext+"\n"
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
        ret["input"]["GeneralStats"] = self.entitiesStats
        ret["input"]["apiosintDSversion"] = self.version
        ret["input"]["scriptinfo"] = scriptinfo
        ret["lookup"] = self.cached
        return ret
