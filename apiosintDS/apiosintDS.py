import sys
import logging
import pytz
import tempfile
import argparse
import os
import requests
import re
import json
italyTZ = pytz.timezone("Europe/Rome")
from apiosintDS.modules import listutils, dosearch
from apiosintDS.modules.scriptinfo import scriptinfo
from apiosintDS.utilities import logutils, prettycli
import validators
import platform


def checkpyversion(logger):
    if (sys.version_info < (3, 0)):#NO MORE PYTHON 2!!! https://pythonclock.org/
        errormessage = """
########################### ERROR ###########################
=============================================================
Invalid python version detected: """+str(sys.version_info[0])+"."+str(sys.version_info[1])+"""
=============================================================
It seems your are still using python 2 even if you should
now it will be retire next 2020.
For more info please read https://pythonclock.org/
=============================================================
Try again typing: python3 """+sys.argv[0]+"""
########################### ERROR ###########################
"""
        logger.error(errormessage)
        exit(0)
        
def nolinuxwarning(logger):
    if platform.system() not in ['Linux']:
        logger.warning("Script not tested on "+platform.system()+" systems. Use at your own risks.")
    
def checkfile(file):
    if os.path.isfile(file) == False:
        msg = "File not found: %r." % file
        raise argparse.ArgumentTypeError(msg)
    else:
        lines = [line.rstrip('\n') for line in open(file)]
        if len(lines) == 0:
            msg2 = "File is empty or unreadable: %r." % file
            raise argparse.ArgumentTypeError(msg2)
    return lines

def checklocalpath(path):
    if os.path.isdir(path) == False:
        msg = "Directory not found: %r." % path
        raise argparse.ArgumentTypeError(msg)
    return path

def writablefile(file):
    if os.path.isfile(file) == True:
        msg = "File %r already exists. Please, delete it first." % file
        raise argparse.ArgumentTypeError(msg)
    else:
        try:
            f = open(file, "w+")
            f.close()
        except:
            msg2 = "Unable to open/create the file: %r." % file
            raise argparse.ArgumentTypeError(msg2)
    return file
    
def writablelog(file):
    if os.path.isfile(file) == True:
        try:
            f = open(file, "a")
            f.close()
        except:
            msg = "File %r already exists. Please, delete it first." % file
            raise argparse.ArgumentTypeError(msg)
    else:
        try:
            f = open(file, "w+")
            f.close()
        except:
            msg2 = "Unable to open/create the file: %r." % file
            raise argparse.ArgumentTypeError(msg2)
    return file

def writablecache(tmpdir):
    if os.path.isfile(tmpdir):
        msg = "%r seems to be a file, not a directory." % tmpdir
        raise argparse.ArgumentTypeError(msg)
    elif os.path.exists(tmpdir) == False:
        msg = "%r directory not found." % tmpdir
        raise argparse.ArgumentTypeError(msg)
    elif os.access(tmpdir, os.W_OK) == False:
        msg = "%r directory not writable." % tmpdir
        raise argparse.ArgumentTypeError(msg)
    return tmpdir
    
def positiveint(val):
    if (int(val) < 0) or (isinstance(int(val), int) == False):
        msg = "Cache timeout must be a positive integer, %r received instead" % val
        raise argparse.ArgumentTypeError(msg)
    return val

def filebspath(directory, file):
	_BSR = os.path.abspath(os.path.dirname(__file__))
	return os.path.join(_BSR, directory, file)

def info():
    htext =  scriptinfo["scriptname"]+" v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]+"."
    htext += "\nOn demand query API for OSINT.digitalside.it project.\n"
    htext += "You can query for souspicious domains, urls and IPv4.\n\n"
    htext += "For more information read the README.md file and the JSON schema hosted on GitHub.com:\n"
    htext += "        - "+scriptinfo["git"]+"/README.md\n"
    htext += "        - "+scriptinfo["git"]+"/schema.json\n"
    htext += "\n"
    htext += "This file is part of the OSINT.digitalside.it project.\n"
    htext += "For more information about the project please visit the following links:\n"
    htext += "        - "+scriptinfo["DSProjectHP"]+"\n"
    htext += "        - "+scriptinfo["DSGitHubHP"]+"\n"
    htext += "\n"
    htext += "This software is released under the "+scriptinfo["license"]+" license\n"
    htext += "        - "+scriptinfo["licenseurl"]+"\n"
    htext += "\n"
    htext += "Coded with love by\n "+scriptinfo["author"]+" <"+scriptinfo["mail"]+">\n"
    htext += " PGP         "+scriptinfo["pgp"]+"\n"
    htext += " Fingerprint "+scriptinfo["fingerprint"]
    htext += "\n"
    return htext
    
def version():
    return scriptinfo["scriptname"]+" v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]

def schema(logger):
    try:
        schema = open(filebspath('schema', 'schema.json'), "r")
        content = schema.read()
        schema.close()
        return content
    except IOError as e:
        logger.error(e)
        logger.error("Unable to load schema file.")
        exit(1)

def request(entities=list, stix=False, cache=False, cachedirectory=None, clearcache=False, cachetimeout=False, verbose=False, loglevel="DEBUG", logconsole=True, logfile=False, localdirectory=False, *args, **kwargs):
    logger = logutils.logutils(loglevel, logfile, logconsole)
    if isinstance(entities, list):
        if localdirectory:
            try:
                checklocalpath(localdirectory)
                cache=False
                cachedirectory=None
                clearcache=False
            except Exception as localdirectoryerror:
                logger.error(localdirectoryerror)
                exit(1)
        if cachetimeout == False:
            cachetimeout = 4            
        if clearcache and ((not cache) or (cache == False)):
            logger.error("Unable to clear cache with cache disabled. Please set the cache to 'True'")
            exit(1)
        if cachedirectory and ((not cache) or (cache == False)):
            logger.error("Unable to use a cache directory with the cache option disabled. Please set the cache to 'True'")
            exit(1)
        if cache and not cachedirectory:
            logger.error("When using apiosintDS as python library, you always have to specify the temporary files directory to be used.")
            exit(1)
        if (isinstance(cachetimeout, int) == False):
            logger.error("Cache timeout must be a positive integer, '"+str(cachetimeout)+"' received instead")
            exit(1)
        if int(cachetimeout) < 0:
            logger.error("Cache timeout must be a positive integer, '"+str(cachetimeout)+"' received instead")
            exit(1)
        if cache:
            try:
                writablecache(cachedirectory)
            except Exception as clearcacheerror:
                logger.error(clearcacheerror)
                exit(1)
                
        lutils = listutils.listutils(None, entities, cache, cachedirectory, clearcache, cachetimeout, localdirectory, logger)
        makelist = lutils.prepareLists()
        if isinstance(makelist, dict):
            serarch = dosearch.dosearch(makelist, verbose, stix, cache, cachedirectory, clearcache, cachetimeout, localdirectory, logger)
            results = serarch.prepareResults()
            if isinstance(results, dict):
                return results
            else:
                logger.error("create_request must return a dict.")
        else:
            logger.error("create_request must return a dict.")
    else:
        logger.error("entities must be an instance of list.")
        exit(1)

def main():
    parserdescription = scriptinfo["scriptname"]+" v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]+"."
    parserdescription +=" On demand query API for OSINT.digitalside.it project."
    parserdescription +=" You can query for souspicious domains, urls and IPv4."
    parser = argparse.ArgumentParser(description=parserdescription)
    parser.add_argument("-e","--entity", type=str, action="store", metavar="[IPv4|domain|url|hash]", dest="ITEM", help="Single item to search. Supported entities are IPv4/FQDN/URLs and file hashes in md5, sha1 or sha256. It can't be used in combination with the --file option.", default=None)
    parser.add_argument("-f","--file", type=checkfile, action="store", metavar="/path/to/file.txt", dest="FILE", help="Path to file containing entities to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --entity option.", default=None)
    parser.add_argument("-st", "--stix", action="store_true", dest="STIX", help="Dowload and parse additional information from STIX report (if available). Default is False.", default=False)
    parser.add_argument("-o", "--output", type=writablefile, action="store", metavar="/path/to/output.json", dest="OUTPUT", help="Path to output file (/path/to/output.json). If not specified the output will be redirect to the STDOUT.", default=False)
    parser.add_argument("-p", "--pretty", action="store_true", dest="PRETTY", help="Show results in terminal with a little bit of formatting applied. Default is False.", default=False)
    parser.add_argument("-nc", "--nocolor", action="store_true", dest="NOCOLOR", help="Suppers colors in --pretty output. For accessibility purpose.", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", dest="VERBOSE", help="Include unmatched results in report. Default is False.", default=False)
    parser.add_argument("-c","--cache", action="store_true", dest="CACHE", help="Enable cache mode. Downloaded lists will be stored a won't be downloaded until the cache timeout period is reached. Default is False.", default=False)
    parser.add_argument("-cd","--cachedirectory", type=writablecache, action="store", metavar="/path/to/cachedir", dest="CACHEDIRECTORY", help="The cache directory where the script check for cached lists files and where them will be stored on cache creation or update. Must be specified the same every script run unless your are using the system temp directory. Default is '"+tempfile.gettempdir()+"'", default=tempfile.gettempdir())
    parser.add_argument("-ct", "--cachetimeout", type=positiveint, action="store", metavar="[0-9]", dest="CACHETIMEOUT", help="Define the cache timeout in hours. 0 is allowed but means no timeout. Default value is 4 hours. This option needs to be used in combination with --cache option configured to True.", default=4)
    parser.add_argument("-cc","--clearcache", action="store_true", dest="CLEARCACHE", help="Force the script to download updated lists and reports even if the cache timeout has not yet been reached. Default is False. Must be used in combination with --cache.", default=False)
    parser.add_argument("-ld","--localdirectory", type=checklocalpath, metavar="/path/to/git/clone/Threat-Intel/", dest="LOCALDIRECTORY", help="Absolute path to the 'Threat-Intel' directory related to local github repository clone. Searches are performed against local data. Before using this option, clone the GitHub project repository. When this option is in use, all cache related options are ignored. Default is False.", default=False)
    parser.add_argument("-ll","--loglevel", type=str, metavar="[DEBUG|INFO|WARNING|ERROR|CRITICAL]", dest="LOGLEVEL", help="Define the log level. Default value is DEBUG.", default="DEBUG")
    parser.add_argument("-l","--logfile", type=writablelog, metavar="/path/to/logfile.log", dest="LOGFILE", help="Define the log file path. Default value is None. No log file is created by default.", default=None)
    parser.add_argument("-lc","--logconsole", action="store_true", dest="LOGCONSOLE", help="Suppress log messages to the console's STDOUT. Default value is False.", default=False)
    parser.add_argument("-i","--info", action="store_true", dest="INFO", help="Print information about the library.")
    parser.add_argument("-s","--schema", action="store_true", dest="SCHEMA", help="Display the response json schema.")
    parser.add_argument("-vv","--version", action="store_true", dest="VERSION", help="Show the library version.")

    try:
        args = parser.parse_args()
        OSDLogger = logutils.logutils(args.LOGLEVEL, args.LOGFILE, args.LOGCONSOLE)
        
        checkpyversion(OSDLogger)
        nolinuxwarning(OSDLogger)
        
        if (args.VERSION):
            sys.stdout.write(version())
            exit(1)
        if (args.INFO):
            sys.stdout.write(info())
            exit(1)
        if (args.SCHEMA):
            try:
                schema = open(filebspath('schema', 'schema.json'), "r")
                for schemaline in schema.readlines():
                    sys.stdout.write(schemaline)
                schema.close()
                exit(0)
            except IOError as e:
                OSDLogger.error(e)
                OSDLogger.error("Unable to load schema file.")
                exit(1)
        if (args.ITEM == None) and (args.FILE == None):
            parser.error("No targets selected! Please, specify one option between --entity and --file.\nTry option -h or --help.")
            OSDLogger.error("No targets selected! Please, specify one option between --entity and --file.\nTry option -h or --help.")
            exit(1)
        elif (args.ITEM != None) and (args.FILE != None):
            parser.error("Too much targets selected! Sorry, you can't specify both options --entity and --file.\nTry option -h or --help.")
            OSDLogger.error("Too much targets selected! Sorry, you can't specify both options --entity and --file.\nTry option -h or --help.")
            exit(1)
        elif args.CLEARCACHE and not args.CACHE:
            args.CLEARCACHE = False
            OSDLogger.warning("Expected -c or --cache option declared. Ignoring all cache settings.\nTry option -h or --help.")
        if args.LOCALDIRECTORY:
            args.CACHE = False
            OSDLogger.info("Detected local copy of the Threat-Intel repository. Cache options will be ignored.")
        if args.PRETTY and args.OUTPUT:
            args.PRETTY = False
            OSDLogger.warning("Detected --output argument in combination with --pretty option. The --pretty option will be ignored.")
        lutils = listutils.listutils(args.ITEM, args.FILE, args.CACHE, args.CACHEDIRECTORY, args.CLEARCACHE, int(args.CACHETIMEOUT), args.LOCALDIRECTORY, OSDLogger)
        makelist = lutils.prepareLists()
        if isinstance(makelist, dict):
            serarch = dosearch.dosearch(makelist, args.VERBOSE, args.STIX, args.CACHE, args.CACHEDIRECTORY, args.CLEARCACHE, int(args.CACHETIMEOUT), args.LOCALDIRECTORY, OSDLogger)
            results = serarch.prepareResults()
            if isinstance(results, dict):
                output = json.dumps(results, indent=4, separators=(",", ": "))
                if args.OUTPUT == False:
                    if args.PRETTY:
                        pretty = prettycli.prettycli(output, args.NOCOLOR, OSDLogger)
                        output = pretty.output
                    sys.stdout.write(output)
                else:
                    fileoutput = open(args.OUTPUT, "w+")
                    fileoutput.write(output)
                    fileoutput.close()
                    OSDLogger.info("Output saved in file: "+args.OUTPUT)
            else:
                OSDLogger.error("'results' is not an dict. Quit!")
        else:
            OSDLogger.error("'makelist' is not an dict. Quit!")
    except argparse.ArgumentError as e:
        OSDLogger.error(e)
        parser.error("Unexpected Error.\nTry option -h or --help.")
        exit(2)

if __name__ == '__main__':
    try:
        main()
    except Exception as detectedError:
        print(detectedError)
        logger.critical(detectedError)
