============================
Usage via command line (CLI)
============================

.. code-block:: bash

	~$ apiosintDS [-h] [-e [IPv4|domain|url|hash]] [-f /path/to/file.txt] [-st] 
	              [-o /path/to/output.json] [-p] [-nc] [-v] [-c] [-cd /path/to/cachedir] 
	              [-ct [0-9]] [-cc] [-ld /path/to/git/clone/Threat-Intel/] 
	              [-l /path/to/logfile.log]  [-ll [DEBUG|INFO|WARNING|ERROR|CRITICAL]] 
	              [-lc] [-i] [-s] [-vv]

Command line options
````````````````````
.. confval:: -h, --help

	Show the help and exit.
 	
	:type: boolean
	:default: ``False``

.. confval:: -e, --entity	
	
	Single item to search. Supported entities are IPv4/FQDN/URLs or file hashes in MD5, SHA1 or SHA256 format.
	
	:type: string
	:default: ``None``
	:allowed: ``[IPv4|domain|url|hash(['md5', 'sha1', 'sha256'])]``
	
	.. note::
		It can't be used in combination with the :confval:`--file` option.

.. confval:: -f, --file	
	
	Path to file containing entities to search. Supported entities are IPv4/FQDN/URLs and file hashes (MD5, SHA1, SHA256).
	Insert one item per row.
	
	:type: string
	:default: ``None``
	:example: ``/path/to/file.txt``
	
	.. note::
		It can't be used in combination with the :confval:`--entity` option.

.. confval:: -st, --stix
	
	Dowload and parse additional information from online STIX report.
	
	:type: boolean
	:default: ``False``
	
	.. note::
		STIX2 reports may be not available due to data retention policy.

.. confval:: -o, --output
	
	Path to output file. If not specified the output will be redirect to the system ``STDOUT``.
	
	:type: string
	:default: ``STDOUT``
	:example: ``/path/to/output.json``
	
	.. note::
		It can't be used in combination with the :confval:`--pretty` option.

.. confval:: -p, --pretty
	
	Show results in terminal with a little bit of formatting applied.
	
	:type: boolean
	:default: ``False``
	
	.. note::
		Default output format is ``JSON``. Data displayed in pretty view
		does not cover all informations included in the JSON response
		format.

.. confval:: -nc, --nocolor
	
	Suppers colors in --pretty output. For accessibility purpose.
	
	:type: boolean
	:default: ``False``
	
.. confval:: -v, --verbose
	
	Include unmatched results in report.
	
	:type: boolean
	:default: ``False``		

.. confval:: -c, --cache
	
	Enable cache mode. Downloaded lists will be stored and won't be downloaded untile the cache timeout is reached.
	
	:type: boolean
	:default: ``False``

.. confval:: -cd, --cachedirectory 
	
	The cache directory where the script check for cached lists files and where them will be stored on cache creation or update.
	
	:type: string
	:default: ``System tmp directory``
	:example: ``/path/to/cachedir``
	
	.. note::
		Must be specified the same every script run unless your are using 			
		the system temp directory.	

.. confval:: -ct, --cachetimeout
	
	Define the cache timeout in hours.
	
	:type: integer
	:default: ``4``
	
	.. note::
		``0`` is allowed but means no timeout. Default value is ``4`` hours. 
		This option needs to be used in combination with :confval:`--cache` option configured to ``True``.	

.. confval:: -cc, --clearcache
	
	Force the script to download updated lists even if the :confval:`--cachetimeout` period has not yet been reached.
	
	:type: boolean
	:default: ``False``
	
	.. note::
		Must be used in combination with :confval:`--cache`			

.. confval:: -ld, --localdirectory
	
	Absolute path to the 'Threat-Intel' directory related to a local project clone. Searches are performed against local data. 
	
	:type: string
	:default: ``False``
	:example: ``/path/to/git/clone/Threat-Intel/``
	
	.. note::
		Before using this option, clone the GitHub project in a file system where 
		the library has read permissions. Don't forget to use ``--depth=1`` and ``--branch=master``
		options if you don't want to download all project commits.
		
		.. code-block:: bash
			
			$ cd /path/to/git/clone/
			$ git clone --depth=1 --branch=master https://github.com/davidonzo/Threat-Intel.git
		
		When this option is in use, all cache related options are ignored. To update data
		in your local repository destroy the existing data and clone it again.
		
		.. code-block:: bash
			
			$ cd /path/to/git/clone/
			$ rm -rf Threat-Intel/
			$ git clone --depth=1 --branch=master https://github.com/davidonzo/Threat-Intel.git

.. confval:: -l, --logfile
	
	Define the log file path.
	
	:type: string
	:default: ``NONE``
	:example: ``/path/to/logfile.log``
	
	.. note::
		No log file is created by default. ``STDOUT`` is used instead.

.. confval:: -ll, --loglevel
	
	Define the log level.
	
	:type: enum
	:default: ``DEBUG``
	:allowed: ``[DEBUG|INFO|WARNING|ERROR|CRITICAL]``

.. confval:: -lc, --logconsole
	
	Suppress log messages to the console's ``STDOUT``.
	
	:type: boolean
	:default: ``False``

.. confval:: -i, --info
	
	Print information about the library.
	
	:type: boolean
	:default: ``False``

.. confval:: -s, --schema
	
	Display the response `json schema <https://github.com/davidonzo/apiosintDS/blob/master/apiosintDS/schema/schema.json>`_.
	
	:type: boolean
	:default: ``False``

.. confval:: -vv, --version
	
	Show the library version.
	
	:type: boolean
	:default: ``False``
