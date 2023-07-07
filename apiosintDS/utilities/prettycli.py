import sys
import json
from apiosintDS.modules.scriptinfo import scriptinfo

class prettycli():
    """
    What a terrible code... -_- please help!
    """
    def __init__(self, results, nocolor, logger):
        self.results = json.loads(results)
        self.logger = logger
        self.nocolor = nocolor
        
        self.HEADER = '\033[95m' if self.nocolor == False else ''
        self.OKBLUE = '\033[94m' if self.nocolor == False else ''
        self.OKCYAN = '\033[96m' if self.nocolor == False else ''
        self.GREEN = '\033[92m' if self.nocolor == False else ''
        self.DARKGREEN = '\033[32m' if self.nocolor == False else ''
        self.WARNING = '\033[93m' if self.nocolor == False else ''
        self.FAIL = '\033[91m' if self.nocolor == False else ''
        self.ORANGE = '\033[93m' if self.nocolor == False else ''
        self.DARKYELL = '\033[33m' if self.nocolor == False else ''
        self.RESET = '\033[0m' if self.nocolor == False else ''
        self.GREY = '\033[37m' if self.nocolor == False else ''
        self.BOLD = '\033[1m' if self.nocolor == False else ''
        self.UNDERLINE = '\033[4m' if self.nocolor == False else ''
        self.output = self.output()
        
        
    def partStix(self, stix):
        ret = {}
        
        timeframe = 0
        if stix["observed_time_frame"]:
            countobtf = len(stix["observed_time_frame"])
            ret["otf"] = stix["observed_time_frame"]
        else:
            ret["otf"] = "N/A"
        counttlp = len(stix["tlp"])
        countfilename = len(stix["filename"])
        countfilesize = len(str(stix["filesize"]))
        countmime_type = len(stix["mime_type"])
        countobser = len(str(stix["number_observed"]))
        
        if countmime_type > 24:
            stix["mime_type"] = stix["mime_type"][:21]+"..."
        
        virustotal = "N/A"
        countvt = 3

        if stix["virus_total"] != False:
            countvt = len(stix["virus_total"]["vt_detection_ratio"])
            virustotal = stix["virus_total"]["vt_detection_ratio"]
        
        fl = " | TLP:"+self.BOLD+stix["tlp"]+self.RESET
        fl += " | First Seen "+self.BOLD+stix["first_observed"]+self.RESET
        fl += " | Last Seen "+self.BOLD+stix["last_observed"]+self.RESET
        ret["fl"] = fl
        ret["flc"] = counttlp+73
        
        ret["fn"] = stix["filename"]
        ret["fnc"] = countfilename
        
        ret["dt"] = " | Size: "+self.BOLD+str(stix["filesize"])+self.RESET
        ret["dt"] += " | Type: "+self.BOLD+stix["mime_type"]+self.RESET
        ret["dt"] += " | Observed: "+self.BOLD+str(stix["number_observed"])+self.RESET
        ret["dt"] += " | VT: "+self.BOLD+virustotal+self.RESET
        
        if "indicators_count" in stix:
            ret["ic"] = " | STIX network indicators: URLs => "+self.BOLD+str(stix["indicators_count"]["urls"])+self.RESET
            ret["ic"] += " | Domains => "+self.BOLD+str(stix["indicators_count"]["domains"])+self.RESET
            ret["ic"] += " | IPs: "+self.BOLD+str(stix["indicators_count"]["ipv4"])+self.RESET
              
        return ret
        

    def parseolReport(self, reports, lenrow, related=False):
        ret = ""
        check = False
        
        countmips = 0
        countcsv = 0
        countods = 0
        countstix = 0
        if "MISP_EVENT" in reports:
            countmips = len(reports["MISP_EVENT"])
            check = True
        if "MISP_CSV" in reports:
            countcsv = len(reports["MISP_CSV"])
            check = True
        if "OSINTDS_REPORT" in reports:
            countods = len(reports["OSINTDS_REPORT"])
            check = True
        if "STIX" in reports:
            check = True
            countstix = len(reports["STIX"])
        
        if check:
            ret += "  "+self.BOLD+self.DARKGREEN+"Online Reports"+self.RESET+self.GREY+" (availability depends on data retention)\n"+self.RESET
        
            if countmips > 0:
                ret +="  -> MISP EVENT: "+reports["MISP_EVENT"]+"\n"
            if countcsv > 0:
                ret +="  -> MISP CSV:   "+reports["MISP_CSV"]+"\n"
            if countods > 0:
                ret +="  -> DS Report:  "+reports["OSINTDS_REPORT"]+"\n"
            if countstix > 0:
                ret +="  -> STIX:       "+reports["STIX"]
        return ret
    
    def parseitem(self, item, related=False, host=False):
        ret = ""
        if related:
            ioc = item["url"]
        else:
            ioc = item["item"]
        
        if ioc.startswith("http"):
            ioc = "hXXp"+ioc[4:]
        else:
            ioc = ioc.replace(".", "[.]")
        coutioc = len(ioc)
        
        padding = 12
        fpadding = 4
        linepadding = 0
        stixpredict = 0
        fncount = 0
        
        fl = False
        if "online_reports" in item:
            if "STIXDETAILS" in item["online_reports"]:
                fl = self.partStix(item["online_reports"]["STIXDETAILS"])  
                stixpredict = fl["flc"]
                fncount = fl["fnc"]
                
        maxrow = (max([coutioc, 77, stixpredict, fncount]))
        if maxrow == coutioc:
            padding = 8
            linepadding = 4
            fpadding = 0
        
        if related:
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            ret += " | "+self.BOLD+self.GREY+ioc.ljust(maxrow-fpadding)+self.RESET+" | \n"
        else:
            if item["response"]:
                ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
                relan = len(item["related_urls"])
                if self.nocolor:
                    countrelan = len(str(relan))+coutioc+2
                else:
                    countrelan = len(str(relan))+coutioc-11
                reltxt = " - Related URL(s) "+self.BOLD+self.FAIL+str(relan)+self.RESET
                if host:
                    if maxrow > 77:
                        if self.nocolor:
                            countrelan = len(str(relan))+18
                        else:
                            countrelan = len(str(relan))
                    ret += " | "+self.BOLD+self.FAIL+ioc+self.GREY+str(reltxt).ljust(maxrow-countrelan)+self.RESET+" | \n"
                else:
                    ret += " | "+self.BOLD+self.FAIL+ioc.ljust(maxrow-fpadding)+self.RESET+" | \n"
            else:
                ioc = ioc+" (not found) "
                if maxrow > 77:
                    linepadding = linepadding+13
                ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
                ret += " | "+self.BOLD+self.GREY+ioc.ljust(maxrow-fpadding)+self.RESET+" | \n"
            
        if fl:
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            linedates = linepadding
            if maxrow > 77:
                if self.nocolor == False:
                    linedates = linedates+23
                else:
                    linedates = linedates-1
            ret += fl["fl"].ljust(maxrow+linedates)+" | "
            ret += "\n"
        
        if "hashes" in item:
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            if fl:
                if len(fl["fn"]) >= maxrow:
                    fl["fn"] = fl["fn"][:maxrow-padding-5]+"..."
                ret += " | Filename: "+self.BOLD+self.FAIL+fl["fn"].ljust(maxrow-padding-2)+self.RESET+" | \n"
                ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            ret += " | MD5:    "+item["hashes"]["md5"].ljust(maxrow-padding)+" | \n"
            ret += " | SHA1:   "+item["hashes"]["sha1"].ljust(maxrow-padding)+" | \n"
            ret += " | SHA256: "+item["hashes"]["sha256"].ljust(maxrow-padding)+" | \n"
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
        else:
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            
        if fl:
            pipepadding = linepadding+8
            if maxrow > 77:
                if self.nocolor == False:
                    pipepadding = pipepadding+23
                else:
                    pipepadding = pipepadding-9
            ret += fl["dt"].ljust(maxrow+pipepadding)+" | \n"
            ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
            if "otf" in fl:
                pipepaddingotf = 28
                if maxrow > 78:
                    if self.nocolor == False:
                        pipepaddingotf = pipepaddingotf
                    else:
                        pipepaddingotf = pipepaddingotf
                ret += " | Observation time frame: "+fl["otf"].ljust(maxrow-pipepaddingotf)+" | \n"
                ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
                
            if "ic" in fl:
                pipepaddingotf = 23
                if self.nocolor:
                    pipepaddingotf = -1
                    
                if maxrow > 78:
                    if self.nocolor == False:
                        pipepaddingotf = pipepaddingotf
                    else:
                        pipepaddingotf = pipepaddingotf
                ret += fl["ic"].ljust(maxrow+pipepaddingotf)+" | \n"
                ret += self.GREY+"  -".ljust(maxrow+linepadding, '-')+self.RESET+"\n"
        
        if "online_reports" in item:
            ret += self.parseolReport(item["online_reports"], maxrow, related)
            ret += "\n"
        return ret
            
    def showsummary(self):
        stats = self.results["generalstatistics"]
        total = stats["itemsSubmitted"]+stats["duplicates"]+stats["invalid"]
        itemsnotfoud = stats["itemsSubmitted"]-stats["itemsFound"]
        emptystring = ""
        
        
        countletterparsed = len(str(total))
        countnotfound = len(str(itemsnotfoud))
        countinvalid = len(str(stats["duplicates"]))
        countduplicates = len(str(stats["duplicates"]))
        countsubmitted = len(str(stats["itemsSubmitted"]))
        countsuburl = len(str(stats["url"]))
        countsubdomain = len(str(stats["domain"]))
        countip = len(str(stats["ip"]))
        countsubhash = len(str(stats["hash"]))
        countfound = len(str(stats["itemsFound"]))
        countfoundurl = len(str(stats["urlfound"]))
        countfounddomain = len(str(stats["domainfound"]))
        countfoundip = len(str(stats["ipfound"]))
        countfoundhash = len(str(stats["hashfound"]))
        
        maxfirstColumn = max([countletterparsed, countinvalid, countduplicates, countnotfound])
        maxsecondColums = max([countsubmitted, countsuburl, countsubdomain, countip, countsubhash])
        maxterColums = max([countfound, countfoundurl, countfounddomain, countfoundip, countfoundhash])
        
        
        Iparsed = "\n | Items parsed: "+str(total).ljust(maxfirstColumn)+self.RESET+" | "
        Iinvalid = "\n | Invalid(s):   "+str(stats["invalid"]).ljust(maxfirstColumn)+self.RESET+" | "
        Iduplicates = "\n | Duplicate(s): "+str(stats["duplicates"]).ljust(maxfirstColumn)+self.RESET+" | "
        Inotfound = "\n | Not found:    "+str(itemsnotfoud).ljust(maxfirstColumn)+self.RESET+" | "
        emptyline = "\n |               "+emptystring.ljust(maxfirstColumn)+" | "
                
        Isumbitted = "Items submitted: "+self.ORANGE+self.BOLD+str(stats["itemsSubmitted"]).ljust(maxsecondColums)+self.RESET+" | " #17
        Iurl = "URL(s):          "+self.ORANGE+self.BOLD+str(stats["url"]).ljust(maxsecondColums)+self.RESET+" | "
        Idomain = "Domain(s):       "+self.ORANGE+self.BOLD+str(stats["domain"]).ljust(maxsecondColums)+self.RESET+" | "
        Iip = "IP(s):           "+self.ORANGE+self.BOLD+str(stats["ip"]).ljust(maxsecondColums)+self.RESET+" | "
        Ihash = "Hash(es):        "+self.ORANGE+self.BOLD+str(stats["hash"]).ljust(maxsecondColums)+self.RESET+" | "
        
        Ifound = "Items found: "+self.FAIL+self.BOLD+str(stats["itemsFound"]).ljust(maxterColums)+self.RESET+" | " #17
        Ifoundurl = "URL(s):      "+self.FAIL+self.BOLD+str(stats["urlfound"]).ljust(maxterColums)+self.RESET+" | "
        Ifounddomain = "Domain(s):   "+self.FAIL+self.BOLD+str(stats["domainfound"]).ljust(maxterColums)+self.RESET+" | "
        Ifoundip = "IP(s):       "+self.FAIL+self.BOLD+str(stats["ipfound"]).ljust(maxterColums)+self.RESET+" | "
        Ifoundhash = "Hash(es):    "+self.FAIL+self.BOLD+str(stats["hashfound"]).ljust(maxterColums)+self.RESET+" | "
        
        maxrow = max([len(Iparsed+Isumbitted+Ifound), 
                      len(Iinvalid+Iurl+Ifoundurl), 
                      len(Iduplicates+Idomain+Ifoundurl), 
                      len(Inotfound+Iip+Ifoundip), 
                      len(emptyline+Ihash+Ifoundhash)])
        
        paddinglines = 33
        if self.nocolor:
            paddinglines = 3
        
        ret = self.BOLD+self.DARKGREEN+" Submission summary\n"+self.RESET
        ret += self.GREY+"  -".ljust(maxrow-paddinglines, '-')+self.RESET
        ret += Iparsed
        ret += Isumbitted
        ret += Ifound
        ret += "\n"+self.GREY+"  -".ljust(maxrow-paddinglines, '-')+self.RESET
        ret += Iinvalid
        ret += Iurl
        ret += Ifoundurl
        ret += Iduplicates
        ret += Ihash
        ret += Ifoundhash
        ret += Inotfound
        ret += Idomain
        ret += Ifounddomain
        ret += emptyline
        ret += Iip
        ret += Ifoundip
        ret += "\n"+self.GREY+"  -".ljust(maxrow-paddinglines, '-')+self.RESET
        ret += "\n"

        return ret
    
    def logo(self):
        version = self.BOLD+self.GREEN+"v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]+self.RESET+self.GREEN
        subtitle = self.ORANGE+scriptinfo["subscriptname"]+self.RESET+self.GREEN
        return """%s
              _           _       _   ____  ____  
   __ _ _ __ (_) ___  ___(_)_ __ | |_|  _ \/ ___| 
  / _` | '_ \| |/ _ \/ __| | '_ \| __| | | \___ \ 
 | (_| | |_) | | (_) \__ \ | | | | |_| |_| |___) |
  \__,_| .__/|_|\___/|___/_|_| |_|\__|____/|____/ %s
       |_|%s%s                             
\n""" % (self.GREEN, version, subtitle, self.RESET)




    def output(self):
        logo = self.logo()
        summary = self.showsummary()

        tmpparseitem = ""
        if "url" in self.results:
            for result in self.results["url"]["items"]:
                tmpparseitem += self.parseitem(result)
                tmpparseitem += self.GREY+"#############################################################################\n\n"+self.RESET
        if "hash" in self.results:
            for result in self.results["hash"]["items"]:
                tmpparseitem += self.parseitem(result)
                tmpparseitem += self.GREY+"#############################################################################\n\n"+self.RESET
        if "ip" in self.results:
            for result in self.results["ip"]["items"]:
                tmpparseitem += self.parseitem(result, False, True)
                if "related_urls" in result:
                    for related in result["related_urls"]:
                        tmpparseitem += self.parseitem(related, True, False)
                    tmpparseitem += self.GREY+"#############################################################################\n\n"+self.RESET
        if "domain" in self.results:
            for result in self.results["domain"]["items"]:
                tmpparseitem += self.parseitem(result, False, True)
                if "related_urls" in result:
                    for related in result["related_urls"]:
                        tmpparseitem += self.parseitem(related, True, False)
                    tmpparseitem += self.GREY+"#".ljust(130, '#')+"\n\n"+self.RESET
            
        ret = logo+summary+tmpparseitem
        return ret
