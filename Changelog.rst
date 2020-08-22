Change Log
=============


0.5.0
+++++

Changes
--------

* Updated exception handling to match libssh API - `ssh.exceptions.SSHError` raised on all non-specific errors.
* Updated authentication exception handling to raise specific authentication errors.
* Added `Session.disconnect` implementation.
* Channel object initialisation now requires Session object to be passed in.


Fixes
------

* Channel deallocation would crash on double free when session channel open failed.


0.4.0
+++++++

Changes
--------

* Updated error handling code to check for SSH status codes and correctly raise exceptions or return error code with no exception in non-blocking mode.
* Updated embedded libssh to ``0.9.4``.
* Added known host session API method implementations.

Packaging
----------

* Added manylinux 2010 binary wheels.
* Added OSX 10.14 and 10.15 binary wheels for Python 3.8
* Added Windows 64-bit binary wheels for Python 3.6/3.7/3.8

0.3.0
++++++++

Changes
-------

* Added SCP support - #3

Packaging
-----------
* Added Linux binary wheels builds.
