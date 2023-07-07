# apiosintDS
Latest stable release is **v2.0**

**apiosintDS** is a [python client library](https://github.com/davidonzo/apiosintDS) for public *API* lookup service over *OSINT* IoCs stored  at [DigitalSide Threat-Intel](https://osint.digitalside.it) repository. It can be defined a **service as a library** tool designed to act both as a standard Python library to be included in your own Python application and as command line tool. Query can be performed against souspicious IPs, domains, urls and file hashes. Data stored has a 7 days retention.

![apiosintDS v2.0](https://raw.githubusercontent.com/davidonzo/apiosintDS/master/docs/_static/img/apiosintDS.png)

[DigitalSide Threat-Intel (also on GitHub.com)](https://github.com/davidonzo/Threat-Intel) shares a set of **Open Source Cyber Threat Intellegence** information, monstly based on malware analysis and compromised URLs, IPs and domains. The purpose of the project is to develop and test new wayes to hunt, analyze, collect and share relevants sets of IoCs to be used by SOC/CSIRT/CERT with minimun effort. 

This library has been specially designed for people and organizations don't want to import the whole [DigitalSide Threat-Intel](https://osint.digitalside.it) dataset and prefer to use it as an on demand service.

## Documentation
Complete documentation availables at [apiosintDS.ReadTheDocs.org](https://apiosintds.readthedocs.io/en/latest/)

## Install
### The easy way via pip
```
~# pip3 install apiosintDS
```

### From sources
```
~$ cd /your/path/src/
~$ git clone https://github.com/davidonzo/apiosintDS.git
~$ python3 -m pip install .
```

## Usage
```
usage: apiosintDS [-h] [-e [IPv4|domain|url|hash]] [-f /path/to/file.txt] [-st] [-o /path/to/output.json] [-p] [-nc] [-v] [-c] [-cd /path/to/cachedir] [-ct [0-9]] [-cc]
                  [-ld /path/to/git/clone/Threat-Intel/] [-ll [DEBUG|INFO|WARNING|ERROR|CRITICAL]] [-l /path/to/logfile.log] [-lc] [-i] [-s] [-vv]

apiosintDS v.2.0. On demand query API for OSINT.digitalside.it project. You can query for souspicious domains, urls and IPv4.

options:
  -h, --help            show this help message and exit
  -e [IPv4|domain|url|hash], --entity [IPv4|domain|url|hash]
                        Single item to search. Supported entities are IPv4/FQDN/URLs and file hashes in md5, sha1 or sha256. It can't be used in combination with the --file option.
  -f /path/to/file.txt, --file /path/to/file.txt
                        Path to file containing entities to search. Supported entities are IPv4/FQDN/URLs. It can't be used in combination with the --entity option.
  -st, --stix           Dowload and parse additional information from STIX report (if available). Default is False.
  -o /path/to/output.json, --output /path/to/output.json
                        Path to output file (/path/to/output.json). If not specified the output will be redirect to the STDOUT.
  -p, --pretty          Show results in terminal with a little bit of formatting applied. Default is False.
  -nc, --nocolor        Suppers colors in --pretty output. For accessibility purpose.
  -v, --verbose         Include unmatched results in report. Default is False.
  -c, --cache           Enable cache mode. Downloaded lists will be stored a won't be downloaded until the cache timeout period is reached. Default is False.
  -cd /path/to/cachedir, --cachedirectory /path/to/cachedir
                        The cache directory where the script check for cached lists files and where them will be stored on cache creation or update. Must be specified the same every script run unless
                        your are using the system temp directory. Default is '/tmp'
  -ct [0-9], --cachetimeout [0-9]
                        Define the cache timeout in hours. 0 is allowed but means no timeout. Default value is 4 hours. This option needs to be used in combination with --cache option configured to
                        True.
  -cc, --clearcache     Force the script to download updated lists and reports even if the cache timeout has not yet been reached. Default is False. Must be used in combination with --cache.
  -ld /path/to/git/clone/Threat-Intel/, --localdirectory /path/to/git/clone/Threat-Intel/
                        Absolute path to the 'Threat-Intel' directory related to local github repository clone. Searches are performed against local data. Before using this option, clone the GitHub
                        project repository. When this option is in use, all cache related options are ignored. Default is False.
  -ll [DEBUG|INFO|WARNING|ERROR|CRITICAL], --loglevel [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                        Define the log level. Default value is DEBUG.
  -l /path/to/logfile.log, --logfile /path/to/logfile.log
                        Define the log file path. Default value is None. No file log will be created by default.
  -lc, --logconsole     Suppress log messages in the console STDOUT. Default value is False.
  -i, --info            Print information about the library.
  -s, --schema          Display the response json schema.
  -vv, --version        Show the library version.

```

### Basic example
```
$ apiosintDS -e 7cb796c875cccc9233d82854a4e2fdf0
{
    "hash": {
        "items": [
            {
                "item": "7cb796c875cccc9233d82854a4e2fdf0",
                "response": true,
                "response_text": "Item found in latesthashes.json list",
                "hashes": {
                    "md5": "7cb796c875cccc9233d82854a4e2fdf0",
                    "sha1": "158514acfa87d0b99e2af07a28004480bbf66e83",
                    "sha256": "49e64d72d5ed4fb7967da4b6851d94cdceffe4ba0316587767a13901fe580239"
                },
                "online_reports": {
                    "MISP_EVENT": "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d6146389-4294-4a41-b4ca-6e74c74b7f8b.json",
                    "MISP_CSV": "https://osint.digitalside.it/Threat-Intel/csv/d6146389-4294-4a41-b4ca-6e74c74b7f8b.csv",
                    "OSINTDS_REPORT": "https://osint.digitalside.it/report/7cb796c875cccc9233d82854a4e2fdf0.html",
                    "STIX": "https://osint.digitalside.it/Threat-Intel/stix2/7cb796c875cccc9233d82854a4e2fdf0.json"
                },
                "related_urls": [
                    "http://185.246.220.60/plugmanzx.exe"
                ]
            }
        ],
        "statistics": {
            "itemsFound": 1,
            "itemsSubmitted": 1
        },
        "list": {
            "file": "latesthashes.json",
            "date": "2023-07-07 08:03:29+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesthashes.json"
        }
    },
    "generalstatistics": {
        "url": 0,
        "ip": 0,
        "domain": 0,
        "hash": 1,
        "invalid": 0,
        "duplicates": 0,
        "itemsFound": 1,
        "itemsSubmitted": 1,
        "urlfound": 0,
        "ipfound": 0,
        "domainfound": 0,
        "hashfound": 1
    },
    "apiosintDSversion": "apiosintDS v.2.0"
}
```

### Example usage: one item using `--pretty`
```
$ apiosintDS -e h[REMOVED]p://193.35.18.147/bins/k.arm -st -p -nc
              _           _       _   ____  ____  
   __ _ _ __ (_) ___  ___(_)_ __ | |_|  _ \/ ___| 
  / _` | '_ \| |/ _ \/ __| | '_ \| __| | | \___ \ 
 | (_| | |_) | | (_) \__ \ | | | | |_| |_| |___) |
  \__,_| .__/|_|\___/|___/_|_| |_|\__|____/|____/ v.2.0
       |_|OSINT.DigitalSide.IT Threat-Intel Repository                             

 Submission summary
  -------------------------------------------------------
 | Items parsed: 1 | Items submitted: 1 | Items found: 1 | 
  -------------------------------------------------------
 | Invalid(s):   0 | URL(s):          1 | URL(s):      1 | 
 | Duplicate(s): 0 | Hash(es):        0 | Hash(es):    0 | 
 | Not found:    0 | Domain(s):       0 | Domain(s):   0 | 
 |                 | IP(s):           0 | IP(s):       0 | 
  -------------------------------------------------------
  ----------------------------------------------------------------------------
 | hXXp://193.35.18.147/bins/k.arm                                            | 
  ----------------------------------------------------------------------------
 | TLP:white | First Seen 2023-07-06 07:36:02 | Last Seen 2023-07-06 07:36:02 | 
  ----------------------------------------------------------------------------
 | Filename: k.arm                                                            | 
  ----------------------------------------------------------------------------
 | MD5:    bc152acad73829358847e5f5bbf3edc0                                   | 
 | SHA1:   f2e26e44709ba5a9766c3c00226bdb663ede5957                           | 
 | SHA256: c8b0e1c5fa98bb407fe5bd3f2760b0ec2e5e33db0cee10a0085cac4505ef16cc   | 
  ----------------------------------------------------------------------------
 | Size: 244647 | Type: application/x-executable | Observed: 1 | VT: 34/61    | 
  ----------------------------------------------------------------------------
 | Observation time frame: N/A                                                | 
  ----------------------------------------------------------------------------
 | STIX network indicators: URLs => 1 | Domains => 0 | IPs: 1                 | 
  ----------------------------------------------------------------------------
  Online Reports (availability depends on data retention)
  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/f5e313d2-3d64-4d0f-af77-37a925bcd08f.json
  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/f5e313d2-3d64-4d0f-af77-37a925bcd08f.csv
  -> DS Report:  https://osint.digitalside.it/report/bc152acad73829358847e5f5bbf3edc0.html
  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/bc152acad73829358847e5f5bbf3edc0.json
#############################################################################
```

### Multiple items using `--file` with `--pretty` output 

Example file ioc.txt
```
~$ cat ioc.txt 
7cb796c875cccc9233d82854a4e2fdf0
monke.re

```

Response
```
~$ apiosintDS -f ioc.txt -p -nc -st

	      _           _       _   ____  ____  
   __ _ _ __ (_) ___  ___(_)_ __ | |_|  _ \/ ___| 
  / _` | '_ \| |/ _ \/ __| | '_ \| __| | | \___ \ 
 | (_| | |_) | | (_) \__ \ | | | | |_| |_| |___) |
  \__,_| .__/|_|\___/|___/_|_| |_|\__|____/|____/ v.2.0
       |_|OSINT.DigitalSide.IT Threat-Intel Repository                             

 Submission summary
  -------------------------------------------------------
 | Items parsed: 2 | Items submitted: 2 | Items found: 2 | 
  -------------------------------------------------------
 | Invalid(s):   0 | URL(s):          0 | URL(s):      0 | 
 | Duplicate(s): 0 | Hash(es):        1 | Hash(es):    1 | 
 | Not found:    0 | Domain(s):       1 | Domain(s):   1 | 
 |                 | IP(s):           0 | IP(s):       0 | 
  -------------------------------------------------------
  ----------------------------------------------------------------------------
 | 7cb796c875cccc9233d82854a4e2fdf0                                           | 
  ----------------------------------------------------------------------------
 | TLP:white | First Seen 2023-07-04 09:33:03 | Last Seen 2023-07-04 09:33:03 | 
  ----------------------------------------------------------------------------
 | Filename: plugmanzx.exe                                                    | 
  ----------------------------------------------------------------------------
 | MD5:    7cb796c875cccc9233d82854a4e2fdf0                                   | 
 | SHA1:   158514acfa87d0b99e2af07a28004480bbf66e83                           | 
 | SHA256: 49e64d72d5ed4fb7967da4b6851d94cdceffe4ba0316587767a13901fe580239   | 
  ----------------------------------------------------------------------------
 | Size: 924672 | Type: application/x-dosexec | Observed: 1 | VT: 32/71       | 
  ----------------------------------------------------------------------------
 | Observation time frame: N/A                                                | 
  ----------------------------------------------------------------------------
 | STIX network indicators: URLs => 1 | Domains => 0 | IPs: 1                 | 
  ----------------------------------------------------------------------------
  Online Reports (availability depends on data retention)
  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d6146389-4294-4a41-b4ca-6e74c74b7f8b.json
  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/d6146389-4294-4a41-b4ca-6e74c74b7f8b.csv
  -> DS Report:  https://osint.digitalside.it/report/7cb796c875cccc9233d82854a4e2fdf0.html
  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/7cb796c875cccc9233d82854a4e2fdf0.json
#############################################################################

  ---------------------------------------------------------------------------
 | monke[.]re - Related URL(s) 2                                              | 
  ---------------------------------------------------------------------------
  ----------------------------------------------------------------------------
 | hXXp://monke.re/arm7                                                       | 
  ----------------------------------------------------------------------------
 | TLP:white | First Seen 2023-07-06 23:51:01 | Last Seen 2023-07-06 23:51:01 | 
  ----------------------------------------------------------------------------
 | Filename: arm7                                                             | 
  ----------------------------------------------------------------------------
 | MD5:    318323c9da34bf25833f7da32eab23d6                                   | 
 | SHA1:   e2bb927b08ebcbaad8f304d02309af776312c9bf                           | 
 | SHA256: bb1f9e108daa389e62b79067d1cdbef548f9934c9cc85a92565da7063cf36f89   | 
  ----------------------------------------------------------------------------
 | Size: 57148 | Type: application/x-executable | Observed: 1 | VT: 14/61     | 
  ----------------------------------------------------------------------------
 | Observation time frame: N/A                                                | 
  ----------------------------------------------------------------------------
 | STIX network indicators: URLs => 1 | Domains => 1 | IPs: 0                 | 
  ----------------------------------------------------------------------------
  Online Reports (availability depends on data retention)
  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/f83d06e6-aa2f-452e-a19d-59d40e874355.json
  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/f83d06e6-aa2f-452e-a19d-59d40e874355.csv
  -> DS Report:  https://osint.digitalside.it/report/318323c9da34bf25833f7da32eab23d6.html
  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/318323c9da34bf25833f7da32eab23d6.json
  ----------------------------------------------------------------------------
 | hXXp://monke.re/mips                                                       | 
  ----------------------------------------------------------------------------
 | TLP:white | First Seen 2023-07-07 00:31:02 | Last Seen 2023-07-07 00:31:02 | 
  ----------------------------------------------------------------------------
 | Filename: mips                                                             | 
  ----------------------------------------------------------------------------
 | MD5:    579081f528d9279a87b298b9838c377b                                   | 
 | SHA1:   45048073aad5997881dffe41e32f9b17beb1c2e1                           | 
 | SHA256: 8186a1d140631e6391978c08c35e01efb58963f65a86fddf7dec44eec7681c6b   | 
  ----------------------------------------------------------------------------
 | Size: 48272 | Type: application/x-executable | Observed: 1 | VT: 12/61     | 
  ----------------------------------------------------------------------------
 | Observation time frame: N/A                                                | 
  ----------------------------------------------------------------------------
 | STIX network indicators: URLs => 1 | Domains => 1 | IPs: 0                 | 
  ----------------------------------------------------------------------------
  Online Reports (availability depends on data retention)
  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.json
  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.csv
  -> DS Report:  https://osint.digitalside.it/report/579081f528d9279a87b298b9838c377b.html
  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/579081f528d9279a87b298b9838c377b.json
##################################################################################################################################
```

[Json schema](https://github.com/davidonzo/apiosintDS/blob/master/apiosintDS/schema/schema.json)

## Python 3 requiremet
The script runs using python intepreter at version 3.x. No support will be given to python 2.x.

