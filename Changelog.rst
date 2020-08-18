Change Log
=============

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

0.3.0
++++++++

Changes
-------

* Added SCP support - #3

Packaging
-----------
* Added Linux binary wheels builds.
