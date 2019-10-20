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
					   		  '10.12.12.10', 
					   		  'somehost.ext', 
					   		  'http://www.example.com/malicious.exe'], 
					   	cache=True, 
					   	cachedirectory="/tmp", 
					   	verbose=True)
		print(OSINTCHECK) # print dict results
	except:
		print("Some error") # some error

Module contents
===============

.. |request| function:: apiosintDS.request(entities=list, cache=False, cachedirectory=None, clearcache=False, verbose=False, *args, **kwargs)

Uniq method to query the service. Return a ``dict`` that can be validated against the json schema returned by the ``apiosintDS.schema()`` method.

Parameters
``````````

	entities *(list)*
		List of entities mixed between IPv4, domains and urls.

	cache *(bool, default=False)*
		Enable cache mode. Downloaded lists will be stored and won't be downloaded for the next 4 hours.

	cachedirectory *(str)*
		The cache directory where the script check for cached lists files and where them will be stored on cache creation or update. Must be specified the same every script run unless your are using the system temp directory. Contrary the CLI usage, there's not a default value).	

	clearcache *(bool, default=False)*
		Force the script to download updated lists even if the 4 hours timeout has not yet been reached. Must be used in combination with *cache* and *cachedirectory*.

	verbose *(bool, default=False)*
		Include unmatched results in returned dict.

.. |schema| function:: apiosintDS.schema()

Return an object containing the ``json`` schema.

