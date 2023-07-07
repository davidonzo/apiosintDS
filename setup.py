#!/usr/bin/env python
import sys
import logging
from apiosintDS.modules.scriptinfo import scriptinfo
logging.basicConfig(format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)
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

from os import path
from setuptools import setup
from codecs import open

requirements = [line.rstrip('\n') for line in open('requirements.txt')]
with open("README.md", "r") as fh:
    mylong_description = fh.read()
scriptinfo = {"scriptname": "apiosintDS",
              "majorversion": "2",
              "minorversion": "0",
              "license": "MIT",
              "licenseurl": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/LICENSE",
              "author": "Davide Baglieri",
              "mail": "info@digitalside.it",
              "pgp": "30B31BDA",
              "fingerprint": "0B4C F801 E8FF E9A3 A602  D2C7 9C36 93B2 30B3 1BDA",
              "git": "https://github.com/davidonzo/Threat-Intel/blob/master/tools/DigitalSide-API/v1",
              "DSProjectHP": "https://osint.digitalside.it",
              "DSGitHubHP": "https://github.com/davidonzo/apiosintDS"}

setup(
	name=scriptinfo["scriptname"],
	packages=["apiosintDS", "apiosintDS.modules", "apiosintDS.utilities"],
	python_requires='>3.5.2',
	version=scriptinfo["majorversion"]+"."+scriptinfo["minorversion"],
	url=scriptinfo["DSGitHubHP"],
	description="On demand query API for OSINT.digitalside.it project. You can query for souspicious domains, urls, IPv4 and file hashes.",
	long_description=mylong_description,
	long_description_content_type="text/markdown",
	license=scriptinfo["license"],
	author=scriptinfo["author"],
	author_email=scriptinfo["mail"],
	keywords=['apiosintDS', 'OSINT', 'Threat-Intel', 'IoC', 'Security'],
	classifiers=[
		"Development Status :: 4 - Beta",
		"Intended Audience :: Information Technology",
		"Topic :: Security",
		"License :: OSI Approved :: MIT License",
		'Programming Language :: Python :: 3'
	],
	package_data={
		'apiosintDS': [
			'schema/schema.json',
			'README.md'
			], 
	},
	install_requires=requirements,

	entry_points={
		"console_scripts": [
			scriptinfo["scriptname"]+"="+scriptinfo["scriptname"]+"."+scriptinfo["scriptname"]+":main",
		],
	},

)
