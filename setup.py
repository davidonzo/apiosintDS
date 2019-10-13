#!/usr/bin/env python
import sys
if (sys.version_info < (3, 0)):#NO MORE PYTHON 2!!! https://pythonclock.org/
    print(" ########################### ERROR ###########################")
    print(" =============================================================")
    print("              Invalid python version detected: "+str(sys.version_info[0])+"."+str(sys.version_info[1]))
    print(" =============================================================")
    print("  It seems your are still using python 2 even if you should")
    print("  now it will be retire next 2020.")
    print("  For more info please read https://pythonclock.org/")
    print(" =============================================================")
    print("  Try again typing: python3 /path/to/"+sys.argv[0])
    print(" =============================================================")
    print(" ########################### ERROR ###########################")
    exit(0)

from os import path
from setuptools import setup
from codecs import open

requirements = [line.rstrip('\n') for line in open('requirements.txt')]
scriptinfo = {"scriptname": "apiosintDS",
              "majorversion": "1",
              "minorversion": "0",
              "license": "MIT",
              "licenseurl": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/LICENSE",
              "author": "Davide Baglieri",
              "mail": "info[at]digitalside.it",
              "pgp": "30B31BDA",
              "fingerprint": "0B4C F801 E8FF E9A3 A602  D2C7 9C36 93B2 30B3 1BDA",
              "git": "https://github.com/davidonzo/Threat-Intel/blob/master/tools/DigitalSide-API/v1",
              "DSProjectHP": "https://osint.digitalside.it",
              "DSGitHubHP": "https://github.com/davidonzo/Threat-Intel"}

setup(
	name=scriptinfo["scriptname"],
	python_requires='>3.5.2',
	version=scriptinfo["majorversion"]+"."+scriptinfo["minorversion"],
	url=scriptinfo["DSGitHubHP"],
	description="On demand query API for OSINT.digitalside.it project. You can query for souspicious domains, urls and IPv4.",
	license=scriptinfo["license"],
	author=scriptinfo["author"],
	author_email=scriptinfo["mail"],
	keywords='apiosintDS',
	classifiers=[
		"Development Status :: 4 - Beta",
		"Intended Audience :: Information Technology",
		"Topic :: Security",
		"License :: OSI Approved :: MIT License",
		'Programming Language :: Python :: 3'
	],
	packages=["apiosintDS", "apiosintDS.modules"],
	
	install_requires=requirements,

	entry_points={
		"console_scripts": [
			scriptinfo["scriptname"]+"="+scriptinfo["scriptname"]+"."+scriptinfo["scriptname"]+":main",
		],
	},

)
