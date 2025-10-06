Installation
*************

Pip Binary Packages
====================

``pip install ssh-python`` will attempt to download a pre-compiled wheel, or try to build from source if one does not exist for the platform.

``pip install -U pip`` to upgrade version of pip, helpful on older Python installations.

Building from Source
=====================

By default, the package will try to build against an embedded version of ``libssh``.

To build against a system library, export the ``SYSTEM_LIBSSH=1`` environment variable prior to building.

Note that the library supports its embedded ``libssh`` version and only that version. Use previous ``ssh-python`` versions if wanting to build against older ``libssh`` versions. See `Changelog <Changelog.html>`_.

The following libraries are required:

* OpenSSL 1.0 or 1.1, >=1.1 for Ed25519 support
* Kerberos 5 for GSSAPI authentication
* Zlib for compression support


Pip Installation Methods
-------------------------

``pip install .`` in the sources root directory will build and install a wheel.

``pip wheel .`` to build a wheel alone.


System Installation Methods
----------------------------

``python setup.py install`` when wanting to make a system package, or to install in ``site-packages``.

``SYSTEM_LIBSSH=1 python setup.py install`` to build against system libssh and install to ``site-packages``.


Building on Windows
--------------------

Requirements:

* Python >= 3.8
* Visual Studio 14 or above
* OpenSSL 1.1
* Zlib
* Kerberos 5 for GSSAPI authentication
* libssh

Steps
++++++

* Build and install dependencies
* Install python package via ``python setup.py install`` or ``pip install .``
  * ``pip wheel .`` as before for creating a wheel.

Note dependencies will need to be built statically to be distributable to other Windows systems.

Cygwin/MingW probably do not work.

No support is offered for building on Windows from source.
