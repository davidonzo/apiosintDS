# DigitalSide-API v.1.8
On demand query API for [OSINT.digitalside.it](https://osint.digitalside.it) project. You can query for souspicious IPs, domains, urls and file hashes.
Searches will be performed against the IoC lists stored in the [GitHub Threat-Intel](https://github.com/davidonzo/Threat-Intel) and [OSINT.DigitalSide.it website](https://osint.digitalside.it/Threat-Intel/lists/)

## Documentation
Complete documentation availables at [apiosintDS.ReadTheDocs.org](https://apiosintds.readthedocs.io/en/latest/)

## Install
### The easy way via pip
```
~# pip3 install apiosintDS
```

### Via python-setuptools
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
  -e [IPv4|domain|url|hash], --entity [IPv4|domain|url|hash]
                        Single item to search. Supported entities are
                        IPv4/FQDN/URLs and file hashes in md5, sha1 or sha256.
                        It can't be used in combination with the --file
                        option.
  -f /path/to/file.txt, --file /path/to/file.txt
                        Path to file containing entities to search. Supported
                        entities are IPv4/FQDN/URLs. It can't be used in
                        combination with the --entity option.
  -o /path/to/output.json, --output /path/to/output.json
                        Path to output file (/path/to/output.json). If not
                        specified the output will be redirect to the STDOUT.
  -v, --verbose         Include unmatched results in report.
  -c, --cache           Enable cache mode. Downloaded lists will be stored a
                        won't be downloaded for the next 4 hours.
  -cd /path/to/cachedir, --cachedirectory /path/to/cachedir
                        The cache directory where the script check for cached
                        lists files and where them will be stored on cache
                        creation or update. Must be specified the same every
                        script run unless your are using the system temp
                        directory. Default is '/tmp'
  -cc, --clearcache     Force the script to download updated lists even if the
                        4 hours timeout has not yet been reached. Must be used
                        in combination with --cachedirectory.
  -i, --info            Print information about the program.
  -s, --schema          Display the response json schema.
```

### Example usage and response for one listed item
```
$ apiosintDS -e 198.12.97.68
{
    "ip": {
        "items": [
            {
                "item": "198.12.97.68",
                "response": true,
                "response_text": "Item found in latestips.txt list",
                "related_urls": [
                    {
                        "url": "http://198.12.97.68/bins/sora.arm",
                        "hashes": {
                            "md5": "b330c76dd7cdea845897615ebdc6fab6",
                            "sha1": "d674d3fbaed43e4276b1f6d7beaf4f7adb9e78c0",
                            "sha256": "85295a1e9b2e176e9a734b8a4ed61cd24b05cd33b1ddefb148fd2149f324e81a"
                        }
                    },
                    {
                        "url": "http://198.12.97.68/bins/sora.arm5",
                        "hashes": {
                            "md5": "06549632f0a7c9cc5e8f2e19792c8d1b",
                            "sha1": "b16b9af9b3260c98f8dcf4f2aae33e3e01603f89",
                            "sha256": "2698619d84fd2caca5b965adb1b5ab048137c8559a5e424a054c2294bb935a31"
                        }
                    },
                    {
                        "url": "http://198.12.97.68/bins/sora.arm6",
                        "hashes": {
                            "md5": "78ed5dd94f31d5d04a6262b36f560d50",
                            "sha1": "28b1dc5f31e6b9d5ee3a633812528df4caa75742",
                            "sha256": "c447c79ef27e30e104739835ebdb35fb8c4f31634fd1d47fae40b77d05201123"
                        }
                    },
                    {
                        "url": "http://198.12.97.68/bins/sora.arm7",
                        "hashes": {
                            "md5": "62e1508ee7acde7ceb7f5d38c16f310c",
                            "sha1": "7c2a048d1cd6257eb51678586bcdab4e3084b147",
                            "sha256": "65ee5bfb8ab755c236222a4de491d12fa4edc3987ed34d7f2c1b7b6b4b6d9123"
                        }
                    }
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latestips.txt",
            "date": "2019-10-22 12:21:59+02:00",
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
9bd12a7cae1de183192bbb2d55fcd3b81fdc51d8

```

Response
```
~$ apiosintDS -f ioc.txt
{
    "url": {
        "items": [
            {
                "item": "http://hellomydearqq.com/80.exe",
                "response": true,
                "response_text": "Item found in latesturls.txt list",
                "hashes": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "related_urls": [
                    {
                        "url": "http://hellomydearqq.com/69.exe",
                        "hashes": {
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        }
                    }
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latesturls.txt",
            "date": "2019-10-22 12:21:59+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesturls.txt"
        }
    },
    "ip": {
        "items": [],
        "statistics": {
            "itemFound": 0,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latestips.txt",
            "date": "2019-10-22 12:21:59+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt"
        }
    },
    "hash": {
        "items": [
            {
                "item": "9bd12a7cae1de183192bbb2d55fcd3b81fdc51d8",
                "response": true,
                "response_text": "Item found in latesthashs.txt list",
                "hashes": {
                    "md5": "09a1a8ac5e3c7875089713570937a7d7",
                    "sha1": "9bd12a7cae1de183192bbb2d55fcd3b81fdc51d8",
                    "sha256": "7fc543adcebae77a2d11726151082a5b8cce3114443f15d3ae52613126304c5d"
                },
                "related_urls": [
                    "http://www.biobharati.com/wp-content/y3a/",
                    "http://lemongrasshostel.net/sdlkitj8kfd/j2y/"
                ]
            }
        ],
        "statistics": {
            "itemFound": 1,
            "itemSubmitted": 1
        },
        "list": {
            "file": "latesthashs.txt",
            "date": "2019-10-22 12:22:00+02:00",
            "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesthashes.txt"
        }
    }
}
```

[Json schema](https://github.com/davidonzo/apiosintDS/blob/master/apiosintDS/schema/schema.json)

## Python 3 requiremet
The script runs using python intepreter at version 3.x. No support will be given to python 2.x.

