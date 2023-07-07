Changelog
=========

2.0 (2023-07-07)
----------------

* Many minor bug fixes
* Implemented python ``getLogger`` as suggested in issue `#2 <https://github.com/davidonzo/apiosintDS/issues/2>`_
* Added `--stix` option. Dowload and parse additional information from online STIX report.
* Added `--pretty` option. Show results in terminal with a little bit of formatting applied.
* Added `--nocolor` option. Suppers colors in –pretty output. For accessibility purpose.
* Added `--cachetimeout` option. Define the cache timeout in hours.
* Added `--localdirectory` option. Absolute path to the ‘Threat-Intel’ directory related to a local project clone. Searches are performed against local data.
* Added `--logfile` option. Define the log file path.
* Added `--loglevel` option. Define the log level.
* Added `--logconsole` option. Suppress log messages to the console’s `STDOUT`.
* Added `--version` option. Show the library version.
* Improved `apiosintDS.request` method according new available options.
* `Documentation updated <https://apiosintds.readthedocs.io/en/latest/>`_

1.8.2 (2019-10-25)
------------------

* Bug fix for cache management of latesthashes.txt list

1.8 (2019-10-22)
----------------

* Added MD5/SHA1/SHA256 strings as entity to search
* Added lookup to hash files for hash entities
* Added support su hash lookup for related urls detected
* Minor bug fixes
* New schema json for response

1.7 (2019-10-20)
----------------

* Added support to be used as standard python library
* Added docs
* Minor bug fixes

1.6 (2019-10-13)
-----------------

* Not a real new release. Just added support to pip.

1.6 (2019-10-13)
-----------------

* First release for python library version usable as CLI tool.
* Added Cache support
* Multiple IoCs submission via text file
* Output management
* New schema response

1.0 (2019-10-07)
-----------------

* Released version 1.0 published on `DigitalSide Threat-Intel <https://github.com/davidonzo/Threat-Intel>`_ repository.

