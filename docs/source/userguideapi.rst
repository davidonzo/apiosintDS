=======================
Using as Python library
=======================

Below a few examples of how to use **apiosintDS** in your code. 

.. code-block:: python

	#!/usr/bin/env python3
	from apiosintDS import apiosintDS

	try:
		OSINTCHECK = apiosintDS.request(
					   	entities=['192.168.1.54', 
					   		  '0a2d170abbf5031566377b01431e3b82d3426301', 
					   		  'somehost.ext', 
					   		  'http://www.example.com/malicious.exe'], 
					   	stix=True
					   	cache=True, 
					   	cachedirectory="/tmp", 
					   	verbose=True)
		print(OSINTCHECK) # print dict results
	except ValueError as e:
		print(e) # some error

Module contents
===============

.. |request| function:: apiosintDS.request(entities=list, stix=False, cache=False, cachedirectory=None, clearcache=False, cachetimeout=False, verbose=False, loglevel="DEBUG", logconsole=True, logfile=False, localdirectory=False, *args, **kwargs)

Uniq method to query the service. Return a ``dict`` that can be validated against the json schema returned by the ``apiosintDS.schema()`` method.

Parameters
``````````

.. confval:: entities	
	
	List of entities to be submitted. One per row.
	
	:type: list
	:default: ``None``
	:allowed: ``[IPv4|domain|url|hash(['md5', 'sha1', 'sha256'])]``

.. confval:: stix
	
	Dowload and parse additional information from online STIX report.
	
	:type: boolean
	:default: ``False``
	
	.. note::
		STIX2 reports may be not available due to data retention policy.

.. confval:: cache
	
	Enable cache mode. Downloaded lists will be stored and won't be downloaded untile the cache timeout is reached.
	
	:type: boolean
	:default: ``False``

.. confval:: cachedirectory 
	
	The cache directory where the script check for cached lists files and where them will be stored on cache creation or update.
	
	:type: string
	:default: ``System tmp directory``
	:example: ``/path/to/cachedir``
	
	.. note::
		Must be specified the same every script run unless your are using 			
		the system temp directory.	

.. confval:: clearcache
	
	Force the script to download updated lists even if the :confval:`cachetimeout` period has not yet been reached.
	
	:type: boolean
	:default: ``False``
	
	.. note::
		Must be used in combination with :confval:`cache`

.. confval:: cachetimeout
	
	Define the cache timeout in hours.
	
	:type: integer
	:default: ``4``
	
	.. note::
		``0`` is allowed but means no timeout. Default value is ``4`` hours. 
		This option needs to be used in combination with :confval:`cache` option configured to True.	

.. confval:: verbose
	
	Include unmatched results in report.
	
	:type: boolean
	:default: ``False``		

.. confval:: loglevel
	
	Define the log level.
	
	:type: enum
	:default: ``DEBUG``
	:allowed: ``[DEBUG|INFO|WARNING|ERROR|CRITICAL]``

.. confval:: logconsole
	
	Suppress log messages to the console's ``STDOUT``.
	
	:type: boolean
	:default: ``True``

.. confval:: logfile
	
	Define the log file path.
	
	:type: string
	:default: ``False``
	:example: ``/path/to/logfile.log``
	
	.. note::
		No log file is created by default. ``STDOUT`` is used instead.

.. confval:: localdirectory
	
	Absolute path to the 'Threat-Intel' directory related to a local project clone. Searches are performed against local data. 
	
	:type: string
	:default: ``False``
	:example: ``/path/to/git/clone/Threat-Intel/``
	
	.. note::
		Before using this option, clone the GitHub project in a file system where 
		the library has read permissions. Don't forget to use `--depth=1` and `--branch=master`
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

.. |schema| function:: apiosintDS.schema()

Return an object containing the ``json`` schema.

