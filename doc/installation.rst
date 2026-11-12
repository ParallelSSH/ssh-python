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

``python -m pip install .`` in the sources root directory will build and install a wheel.

``python -m pip wheel --no-deps .`` to build a wheel alone.

``SYSTEM_LIBSSH=1 python -m pip install .`` to build against system libssh.


Building Distributions
----------------------

Install the build frontend with ``python -m pip install build``.

``python -m build`` builds a source distribution and then a wheel from it,
placing both in ``dist/``.

Use ``python -m build --sdist`` or ``python -m build --wheel`` to build only
one distribution format.


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
* Install the build dependencies with
  ``python -m pip install build wheel "setuptools>=61.0" "versioneer[toml]>=0.29" cython``.
* Install the Python package via ``python -m pip install --no-build-isolation .``.
* To build a wheel instead, use ``python -m build --wheel --no-isolation``.

Windows builds need Cython to regenerate platform-specific C sources. Build
isolation is disabled here so that the build can use the installed Cython.

Note dependencies will need to be built statically to be distributable to other Windows systems.

Cygwin/MingW probably do not work.

No support is offered for building on Windows from source.
