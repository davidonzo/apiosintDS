============================
Usage via command line (CLI)
============================

.. code-block:: bash

	~$ apiosintDS [-h] [-e [IPv4|domain|url]] [-f /path/to/file.txt] 
                      [-o /path/to/output.json] [-v] [-c] [-cd /path/to/cachedir]
                      [-cc] [-i] [-s]

Command line options
````````````````````

	-h, --help 
		Show the help and exit.
		
	-e, --entity [IPv4|domain|url]			
		Single item to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --file option.
		
	-f, --file [/path/to/file.txt]			
		Path to file containing entities to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --entity option.
		
	-o, --output [/path/to/output.json]		
		Path to output file (/path/to/output.json). If not specified the output will be redirect to the system STDOUT.
		
	-v, --verbose					
		Include unmatched results in report.
		
	-c, --cache           				
		Enable cache mode. Downloaded lists will be stored and won't be downloaded for the next 4 hours.
		
	-cd, --cachedirectory [/path/to/cachedir]	
		The cache directory where the script check for cached lists files and where them will be stored on cache creation or update. Must be specified the same every script run unless your are using the system temp directory. Default is the temporary user directory.
		
	-cc, --clearcache     				
		Force the script to download updated lists even if the 4 hours timeout has not yet been reached. Must be used in combination with --cache.
		
	-i, --info            				
		Print information about the program.
		
	-s, --schema          				
		Display the response `json schema <https://github.com/davidonzo/apiosintDS/blob/master/apiosintDS/schema/schema.json>`_.
	

Example usage and response for one listed item
==============================================

.. code-block:: bash

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

Example usage and response submitting a file
============================================

Example file ioc.txt.

.. code-block:: bash

	~$ cat ioc.txt 
	104.217.254.20
	helloyoungmanqq.com
	http://hellomydearqq.com/80.exe

Response.

.. code-block:: bash

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


