Change Log
=============

1.1.1
+++++

Changes
--------

No code changes.


Packaging
----------

* Added Windows Python 3.7 and 3.13 wheel builds.
* Removed manylinux 2010 wheels.
* Wheel builds now use embedded libssh.
* Source distribution now uses embedded libssh.
* Added embedded krb5 for wheel builds.
* Dockerfiles and scripts updates.


1.1.0
+++++

Changes
--------

* Updated embedded and manylinux libssh to `0.11.1`.
* Support for Python >=3.12.
* Upgraded wheel OpenSSL to 3.4.0.
* Removed testing for Python versions <3.8.

Packaging
----------

* Added binary wheels for Python versions 3.11, 3.12 and 3.13 on support manylinux wheel builds.
* Added OSX 12.0, 13.0 and 14.0 wheels, Apple Silicon.
* Support OSX brew OpenSSL from source builds.
* Top level tests directory is now cross platform and can be run by vendors.
* Moved CI specific integration tests to their own space.


1.0.0
++++++

Changes
--------

* Updated embedded and manylinux libssh to ``0.10.4`` - thank you @enkore

Packaging
----------

* Upgraded wheel OpenSSL to 1.1.1q.
* Added testing for Python 3.11, removed 3.10.
* Added Windows wheel build for Python 3.11.
* Added OSX 12.0 wheels.
* Removed OSX <= 10.0 wheels.

0.10.0
++++++

Changes
-------

* Added missing options in ``ssh.options`` - #42, thank you @enkore

Packaging
----------

* Updated embedded and manylinux libssh to ``0.9.6`` - thank you @enkore
* Manylinux wheels are now smaller, disabled debug symbols - #43, thank you @enkore
* Added manylinux-2014 wheels for AMD64 and ARM (AArch64), all supported Python versions
* Added OSX 11.6, 11.5 and 11.4 wheels.
* Removed OSX 10.x versions wheels.
* Added Windows 3.10 wheel build

0.9.0
+++++

Changes
-------

* ``ssh.Channel.write`` and ``write_stderr`` now return return code and bytes written tuples.


Fixes
-----

* ``ssh.key.generate`` could not be used.
* Key types in ``ssh.keytypes`` were not initialised correctly.


Packaging
---------

* Added Windows Python 3.9 binary wheel.


0.8.0
+++++

Changes
--------

* Updated supported key types in ``ssh.keytypes`` for libssh 0.9.5.
* Added certificate import and handling functions to ``ssh.key``

Packaging
---------

* Updated OpenSSL in manylinux wheels to 1.1
* Added Python 3.9 Windows 64-bit binary wheel

0.7.0
+++++

Changes
-------

* Updated embedded libssh to ``0.9.5``.
* ``Session.channel_new`` now raises ``ssh.exceptions.ChannelOpenFailure`` on failure to create new channel.

0.6.0
+++++

Changes
--------

* Added function for setting GSS-API credentials delegation option to session.
* Updated error handling for all user authentication session functions to raise specific authentication errors.
* `ssh.Key.import_privkey_*` now defaults to empty passphrase.


0.5.0
+++++

Changes
--------

* Updated exception handling to match libssh API - `ssh.exceptions.SSHError` raised on all non-specific errors.
* Updated authentication exception handling to raise specific authentication errors.
* Channel object initialisation now requires Session object to be passed in.


Fixes
------

* Channel deallocation would crash on double free when session channel open failed.


0.4.0
+++++++

Changes
--------

* Updated error handling code to check for SSH status codes and correctly raise exceptions or return error code with no
  exception in non-blocking mode.
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
