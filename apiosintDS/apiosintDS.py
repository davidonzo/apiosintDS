import sys
import logging
import pytz
logging.basicConfig(format='%(levelname)s: %(message)s')
if (sys.version_info < (3, 0)):#NO MORE PYTHON 2!!! https://pythonclock.org/
    logging.error(" ########################### ERROR ###########################")
    logging.error(" =============================================================")
    logging.error("              Invalid python version detected: "+str(sys.version_info[0])+"."+str(sys.version_info[1]))
    logging.error(" =============================================================")
    logging.error("  It seems your are still using python 2 even if you should")
    logging.error("  now it will be retire next 2020.")
    logging.error("  For more info please read https://pythonclock.org/")
    logging.error(" =============================================================")
    logging.error("  Try again typing: python3 /path/to/"+sys.argv[0])
    logging.error(" =============================================================")
    logging.error(" ########################### ERROR ###########################")
    exit(0)
import tempfile
import argparse
import os
import requests
import re
import json
italyTZ = pytz.timezone("Europe/Rome")
from apiosintDS.modules import listutils, dosearch
try:
    from urllib.parse import urlparse
except ImportError as ierror:
    logging.error(ierror)
    logging.error("To run this script you need to install the \"urllib\" module")
    logging.error("Try typing: \"pip3 install urllib3\"")
    exit(0)
try:
    import validators
except ImportError as e:
    logging.error(e)
    logging.error("To run this script you need to install the \"validators\" module")
    logging.error("Try typing: \"pip3 install validators\"")
    exit(0)
import platform
if platform.system() not in ['Linux']:
    logging.warning("Script not testes on "+platform.system()+" systems. Use at your own risks.")
    
scriptinfo = {"scriptname": "DigitalSide-API",
              "majorversion": "1",
              "minorversion": "7",
              "license": "MIT",
              "licenseurl": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/LICENSE",
              "author": "Davide Baglieri",
              "mail": "info[at]digitalside.it",
              "pgp": "30B31BDA",
              "fingerprint": "0B4C F801 E8FF E9A3 A602  D2C7 9C36 93B2 30B3 1BDA",
              "git": "https://github.com/davidonzo/Threat-Intel/blob/master/tools/DigitalSide-API/v1",
              "DSProjectHP": "https://osint.digitalside.it",
              "DSGitHubHP": "https://github.com/davidonzo/Threat-Intel"}
    
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

def writablefile(file):
    if os.path.isfile(file) == True:
        msg = "File %r already exists. Please, delete it first." % file
        raise argparse.ArgumentTypeError(msg)
    else:
        try:
            f = open(file, "w+")
            f.close()
        except:
            msg2 = "File is empty or unreadable: %r." % file
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
        msg = "%r directory not found." % tmpdir
        raise argparse.ArgumentTypeError(msg)
    return tmpdir

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

def schema():
    try:
        schema = open(filebspath('schema', 'schema.json'), "r")
        content = schema.read()
        schema.close()
        return content
    except IOError as e:
        logging.error(e)
        logging.error("Unable to load schema file.")
        exit(1)

def request(entities=list, cache=False, cachedirectory=None, clearcache=False, verbose=False, *args, **kwargs):
    if isinstance(entities, list):
        if clearcache and ((not cache) or (cache == False)):
            logging.error("Unable to clear cache with cache disabled. Please set the cache to 'True'")
            exit(1)
        if cachedirectory and ((not cache) or (cache == False)):
            logging.error("Unable to use a cache directory with the cache option disabled. Please set the cache to 'True'")
            exit(1)
        if cache and not cachedirectory:
            logging.error("When using apiosintDS as python library, you always have to specify the temporary files directory to be used.")
            exit(1)
        if cache:
            try:
                writablecache(cachedirectory)
            except Exception as clearcacheerror:
                logging.error(clearcacheerror)
                exit(1)
                
        lutils = listutils.listutils(None, entities, cache, cachedirectory, clearcache)
        makelist = lutils.prepareLists()
        if isinstance(makelist, dict):
            serarch = dosearch.dosearch(makelist, verbose)
            results = serarch.prepareResults()
            if isinstance(results, dict):
                return results
            else:
                logging.error("create_request must return a dict.")
        else:
            logging.error("create_request must return a dict.")
    else:
        logging.error("entities must be an instance of list.")
        exit(1)

def main():
    parserdescription = scriptinfo["scriptname"]+" v."+scriptinfo["majorversion"]+"."+scriptinfo["minorversion"]+"."
    parserdescription +=" On demand query API for OSINT.digitalside.it project."
    parserdescription +=" You can query for souspicious domains, urls and IPv4."
    parser = argparse.ArgumentParser(description=parserdescription)
    parser.add_argument("-e","--entity", type=str, action="store", metavar="[IPv4|domain|url]", dest="ITEM", help="Single item to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --file option.", default=None)
    parser.add_argument("-f","--file", type=checkfile, action="store", metavar="/path/to/file.txt", dest="FILE", help="Path to file containing entities to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --entity option.", default=None)
    parser.add_argument("-o", "--output", type=writablefile, action="store", metavar="/path/to/output.json", dest="OUTPUT", help="Path to output file (/path/to/output.json). If not specified the output will be redirect to the STDOUT.", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", dest="VERBOSE", help="Include unmatched results in report.")
    parser.add_argument("-c","--cache", action="store_true", dest="CACHE", help="Enable cache mode. Downloaded lists will be stored a won't be downloaded for the next 4 hours.")
    parser.add_argument("-cd","--cachedirectory", type=writablecache, action="store", metavar="/path/to/cachedir", dest="DIRECTORY", help="The cache directory where the script check for cached lists files and where them will be stored on cache creation or update. Must be specified the same every script run unless your are using the system temp directory. Default is '"+tempfile.gettempdir()+"'", default=tempfile.gettempdir())
    parser.add_argument("-cc","--clearcache", action="store_true", dest="CLEARCACHE", help="Force the script to download updated lists even if the 3 hours timeout has not yet been reached. Must be used in combination with --cache.")
    parser.add_argument("-i","--info", action="store_true", dest="INFO", help="Print information about the program.")
    parser.add_argument("-s","--schema", action="store_true", dest="SCHEMA", help="Display the response json schema.")

    try:
        args = parser.parse_args()
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
                logging.error(e)
                logging.error("Unable to load schema file.")
                exit(1)
        if (args.ITEM == None) and (args.FILE == None):
            parser.error("No targets selected! Please, specify one option between --entity and --file.\nTry option -h or --help.")
            exit(1)
        elif (args.ITEM != None) and (args.FILE != None):
            parser.error("Too much targets selected! Sorry, you can't specify both options --entity and --file.\nTry option -h or --help.")
            exit(1)
        elif args.CLEARCACHE and not args.CACHE:
            args.CLEARCACHE = False
            logging.warning("Expected -c or --cache option declared. Ignoring all cache settings.\nTry option -h or --help.")
        lutils = listutils.listutils(args.ITEM, args.FILE, args.CACHE, args.DIRECTORY, args.CLEARCACHE)
        makelist = lutils.prepareLists()
        if isinstance(makelist, dict):
            serarch = dosearch.dosearch(makelist, args.VERBOSE)
            results = serarch.prepareResults()
            if isinstance(results, dict):
                output = json.dumps(results, indent=4, separators=(",", ": "))
                if args.OUTPUT == None:
                    sys.stdout.write(output)
                else:
                    fileoutput = open(args.OUTPUT, "w+")
                    fileoutput.write(output)
                    fileoutput.close()
                    logging.info("Output saved in file: "+args.OUTPUT)
            else:
                logging.error("'results' is not an dict. Quit!")
        else:
            logging.error("'makelist' is not an dict. Quit!")
    except argparse.ArgumentError as e:
        logging.error(e)
        parser.error("Unexpected Error.\nTry option -h or --help.")
        exit(2)

if __name__ == '__main__':
    main()
