==================
Installation guide
==================

Install python > 3.5.2
======================

Make sure you installed on your system python > 3.5.2. Try typing ``python3`` on your terminal. 

.. code-block:: bash

	~$ python3
	Python 3.6.8 (default, Oct  7 2019, 12:59:55) 
	[GCC 8.3.0] on linux
	Type "help", "copyright", "credits" or "license" for more information.
	>>> 

Install from sources
====================

Make sure you installed ``python3-setuptools`` and ``git`` packages on your system. If not, install missings according your distribution.

.. code-block:: bash

    ~$ cd /your/path/src/
    ~$ git clone https://github.com/davidonzo/apiosintDS.git
    ~$ cd apiosintDS/
    ~$ python3 -m pip install .

Install via pip3
================

Make sure you installed ``python3-pip`` package on your system. If not, install it according your distribution.

.. code-block:: bash

    ~$ pip3 install apiosintDS

Windows support
===============

The library has never been tested on Windows platform. Actually only UNIX system are supported.
