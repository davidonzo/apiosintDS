# DigitalSide-API v.0.1
On demand query API for OSINT.digitalside.it project. You can query for souspicious IPs (just IPv4 supported at the moment), domains and urls.

## Install
```
~$ cd /your/path/src/
~$ git clone https://github.com/davidonzo/apiosintDS.git
~$ cd apiosintDS/
~$ python3 setup.py build
~$ sudo python3 setup.py install
```

## Usage
```
~$ apiosintDS -h
usage: apiosintDS [-h] [-e [IPv4|domain|url]] [-f /path/to/file.txt]
                  [-o /path/to/output.json] [-v] [-c] [-cd /path/to/cachedir]
                  [-cc] [-i] [-s]

DigitalSide-API v.1.0. On demand query API for OSINT.digitalside.it project.
You can query for souspicious domains, urls and IPv4.

optional arguments:
  -h, --help            show this help message and exit
  -e [IPv4|domain|url], --entity [IPv4|domain|url]
                        Single item to search. Supported entities are
                        IPv4/FQDN/URLs. It can't be used in combination with
                        the --file option.
  -f /path/to/file.txt, --file /path/to/file.txt
                        Path to file containing entities to search. Supported
                        entities are IPv4/FQDN/URLs. It can't be used in
                        combination with the --entity option.
  -o /path/to/output.json, --output /path/to/output.json
                        Path to output file (/path/to/output.json). If not
                        specified the output will be redirect to the STDOUT.
  -v, --verbose         Include unmatched results in report.
  -c, --cache           Enable cache mode. Downloaded lists will be stored a
                        won't be downloaded for the next 3 hours.
  -cd /path/to/cachedir, --cachedirectory /path/to/cachedir
                        The cache directory where the script check for cached
                        lists files and where them will be stored on cache
                        creation or update. Must be specified the same every
                        script run unless your are using the system temp
                        directory. Default is '/tmp'
  -cc, --clearcache     Force the script to download updated lists even if the
                        3 hours timeout has not yet been reached. Must be used
                        in combination with --cachedirectory.
  -i, --info            Print information about the program.
  -s, --schema          Display the response json schema.
```

### Example usage and response for one listed item
```
~$ apiosintDS -e 104.217.254.20
{
    "ip": {
        "items": [
            {
                "item": "104.217.254.20",
                "response": true,
                "response_text": "Item found in latestips.txt list",
                "related_urls": [
                    "http://104.217.254.20/bins/hoho.arm5",
                    "http://104.217.254.20/bins/hoho.arm6",
                    "http://104.217.254.20/bins/hoho.arm7",
                    "http://104.217.254.20/bins/hoho.m68k",
                    "http://104.217.254.20/bins/hoho.mips",
                    "http://104.217.254.20/bins/hoho.x86"
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latestips.txt",
            "date": "2019-10-13 20:15:12+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt"
        }
    }
}
```

### Example usage and response submitting a file containing various entities

Example file ioc.txt
```
~$ cat ioc.txt 
104.217.254.20
helloyoungmanqq.com
http://hellomydearqq.com/80.exe
```

Response
```
{
    "url": {
        "items": [
            {
                "item": "http://hellomydearqq.com/80.exe",
                "response": true,
                "response_text": "Item found in latesturls.txt list",
                "related_urls": [
                    "http://hellomydearqq.com/69.exe"
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latesturls.txt",
            "date": "2019-10-13 20:15:12+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesturls.txt"
        }
    },
    "ip": {
        "items": [
            {
                "item": "104.217.254.20",
                "response": true,
                "response_text": "Item found in latestips.txt list",
                "related_urls": [
                    "http://104.217.254.20/bins/hoho.arm5",
                    "http://104.217.254.20/bins/hoho.arm6",
                    "http://104.217.254.20/bins/hoho.arm7",
                    "http://104.217.254.20/bins/hoho.m68k",
                    "http://104.217.254.20/bins/hoho.mips",
                    "http://104.217.254.20/bins/hoho.x86"
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latestips.txt",
            "date": "2019-10-13 20:15:12+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt"
        }
    },
    "domain": {
        "items": [
            {
                "item": "helloyoungmanqq.com",
                "response": true,
                "response_text": "Item found in latestdomains.txt list",
                "related_urls": [
                    "http://helloyoungmanqq.com/25.exe",
                    "http://helloyoungmanqq.com/26.exe",
                    "http://helloyoungmanqq.com/34.exe",
                    "http://helloyoungmanqq.com/34.jpg",
                    "http://helloyoungmanqq.com/45.exe",
                    "http://helloyoungmanqq.com/45.jpg",
                    "http://helloyoungmanqq.com/59.exe",
                    "http://helloyoungmanqq.com/59.jpg",
                    "http://helloyoungmanqq.com/70.exe",
                    "http://helloyoungmanqq.com/70.jpg",
                    "http://helloyoungmanqq.com/80.exe",
                    "http://helloyoungmanqq.com/80.jpg",
                    "http://helloyoungmanqq.com/85.exe",
                    "http://helloyoungmanqq.com/85.jpg",
                    "http://helloyoungmanqq.com/87.exe",
                    "http://helloyoungmanqq.com/87.jpg",
                    "http://helloyoungmanqq.com/93.exe",
                    "http://helloyoungmanqq.com/93.jpg"
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latestdomains.txt",
            "date": "2019-10-13 20:15:12+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt"
        }
    }
}
```

[Json schema](https://github.com/davidonzo/apiosintDS/blob/master/apiosintDS/schema/schema.json)
```
{
  "$schema": "http://json-schema.org/schema#",
  "title": "Validator for DigitalSide-API response",
  "id": "https://github.com/davidonzo/Threat-Intel/tools/DigitalSide-API/schema.json",
  "properties": {
    "item": {
      "type": "string",
      "description": "The entity to search using DigitalSide-API"
    },
    "item_type": {
      "type": "string",
      "enum": ["domain", "ip", "url"],
      "description": "The entity type, that can be an URL, an IP or a domain name"
    },
    "response": {
      "type": "boolean",
      "description": "True if a match has been found. False if no match has been found"
    },
    "response_text": {
      "type": "string",
      "description": "Just a human readble representation of the 'response' item"
    },
    "related_urls": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "description": "The related URLs associated to the submitted item. If no related IoC found, the list will be empty"
        }
      ]
    },
    "list_date": {
      "type": "string",
      "description": "The published datetime of the downloaded list"
      
    },
    "list_link": {
      "type": "string"
    }
  },
  "required": [
    "item",
    "item_type",
    "response",
    "response_text",
    "related_urls",
    "list_date",
    "list_link"
  ]
}
```

## Python 3 requiremet
The script runs using python intepreter at version 3.x. No support will be given to python 2.x.

